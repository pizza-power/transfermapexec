package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unicode"
)

// closerFunc adapts a function to io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// idleConn is a net.Conn whose every read and write must complete within d,
// so a peer that stops sending (or reading) is dropped instead of holding the
// connection open forever.
type idleConn struct {
	net.Conn
	d time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.d))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.d))
	return c.Conn.Write(p)
}

// acceptLoop hands every connection ln accepts to handle, in its own
// goroutine, until ln is closed.
func acceptLoop(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		go handle(c)
	}
}

// Stream methods without a protocol of their own (tcp, tls, quic) end with a
// one-line verdict from the server: "OK" or "ERR <reason>".

func writeVerdict(w io.Writer, err error) {
	if err == nil {
		_, _ = io.WriteString(w, "OK\n")
		return
	}
	_, _ = fmt.Fprintf(w, "ERR %s\n", oneLine(err.Error()))
}

func readVerdict(r io.Reader) error {
	line, err := bufio.NewReader(r).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	switch {
	case line == "OK":
		return nil
	case strings.HasPrefix(line, "ERR "):
		return &refusedError{line[4:]}
	case err != nil && line == "":
		if errors.Is(err, io.EOF) {
			return errors.New("server closed the connection without confirming delivery")
		}
		return fmt.Errorf("no delivery confirmation from server: %w", err)
	default:
		return fmt.Errorf("unexpected reply from server: %q", line)
	}
}

// refusedError is the server saying it did not store the data, with its reason.
type refusedError struct{ reason string }

func (e *refusedError) Error() string { return "server refused the transfer: " + e.reason }

// oneLine flattens s onto a single line of at most 200 bytes, for error
// messages that travel back to the client inside a protocol.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// rtoEstimator adapts the resend timeout of the datagram methods to the
// measured round-trip time (the TCP algorithm, RFC 6298, in miniature), so a
// lost packet costs a few round trips instead of a fixed half second.
type rtoEstimator struct {
	srtt, rttvar time.Duration
	rto          time.Duration
	min, max     time.Duration
}

// newRTO starts at max (nothing has been measured yet) and never goes below min.
func newRTO(min, max time.Duration) *rtoEstimator {
	return &rtoEstimator{rto: max, min: min, max: max}
}

// sample records the round trip of a packet that was sent exactly once
// (Karn's rule: the reply to a resent packet says nothing about the RTT).
func (e *rtoEstimator) sample(d time.Duration) {
	if e.srtt == 0 {
		e.srtt, e.rttvar = d, d/2
	} else {
		diff := e.srtt - d
		if diff < 0 {
			diff = -diff
		}
		e.rttvar = (3*e.rttvar + diff) / 4
		e.srtt = (7*e.srtt + d) / 8
	}
	e.rto = min(max(e.srtt+4*e.rttvar, e.min), e.max)
}

// backoff doubles the timeout after a loss, up to max.
func (e *rtoEstimator) backoff() { e.rto = min(2*e.rto, e.max) }

// idleGuard cancels a transfer that has stopped making progress. Each method
// touches it when data moves (the frame is read for sending, or the server
// acknowledges something), so a transfer of any size runs for as long as it
// needs, provided it keeps moving.
type idleGuard struct {
	timer *time.Timer
	d     time.Duration
}

// newIdleGuard calls cancel if the first progress does not come within first,
// or if any later gap between progress is longer than d.
func newIdleGuard(first, d time.Duration, cancel context.CancelCauseFunc) *idleGuard {
	g := &idleGuard{d: d}
	g.timer = time.AfterFunc(first, func() {
		cancel(fmt.Errorf("transfer stalled: no progress for %s (-idle-timeout)", d))
	})
	return g
}

func (g *idleGuard) touch() { g.timer.Reset(g.d) }
func (g *idleGuard) stop()  { g.timer.Stop() }

// reader wraps r so that every read that returns data counts as progress.
func (g *idleGuard) reader(r io.Reader) io.Reader { return guardedReader{r, g} }

type guardedReader struct {
	r io.Reader
	g *idleGuard
}

func (gr guardedReader) Read(p []byte) (int, error) {
	n, err := gr.r.Read(p)
	if n > 0 {
		gr.g.touch()
	}
	return n, err
}
