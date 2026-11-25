package main

// A small reliable-transfer protocol for the methods that can only carry
// short, unreliable messages: udp, dns and icmp. Each method just wraps and
// unwraps messages (a UDP payload, a DNS query name and TXT answer, a ping
// payload); this file does the rest.
//
// The client splits the frame into fixed-size chunks and sends them with a
// sliding window. The server acknowledges every message; anything not
// acknowledged in time is sent again. Requests (client to server):
//
//	[2] magic "MT"   [1] type   [4] session id   [4] seq   [...] body
//
//	INIT  seq 0       body: [8] frame size, [2] chunk size
//	DATA  seq = chunk index, body: the chunk
//	FIN   seq = number of chunks; the reply to FIN is the verdict
//
// Replies (server to client):
//
//	[2] magic "MR"   [1] type   [4] session id   [4] seq   [1] status   [...] error text
//
// The server feeds chunks to the usual frame receiver in order, buffering a
// bounded number that arrive early, so nothing is written to a temporary
// reassembly file.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"syscall"
	"time"
)

const (
	dgReqMagic = "MT"
	dgRepMagic = "MR"
	dgHdrLen   = 2 + 1 + 4 + 4

	dgInit byte = 1
	dgData byte = 2
	dgFin  byte = 3

	dgStatusOK  byte = 0
	dgStatusErr byte = 1

	// dgReorder is how far past the next expected chunk the server buffers
	// chunks that arrive early. Client windows must not exceed it.
	dgReorder = 256

	// dgMaxSessions bounds the transfers a server tracks at once.
	dgMaxSessions = 256

	// dgMaxErrText keeps error replies small enough for a DNS TXT record.
	dgMaxErrText = 120
)

func dgEncode(magic string, typ byte, sid, seq uint32, body []byte) []byte {
	b := make([]byte, 0, dgHdrLen+len(body))
	b = append(b, magic...)
	b = append(b, typ)
	b = binary.BigEndian.AppendUint32(b, sid)
	b = binary.BigEndian.AppendUint32(b, seq)
	return append(b, body...)
}

func dgParse(msg []byte, magic string) (typ byte, sid, seq uint32, body []byte, ok bool) {
	if len(msg) < dgHdrLen || string(msg[:2]) != magic {
		return 0, 0, 0, nil, false
	}
	return msg[2], binary.BigEndian.Uint32(msg[3:7]), binary.BigEndian.Uint32(msg[7:11]), msg[dgHdrLen:], true
}

func dgReply(typ byte, sid, seq uint32, err error) []byte {
	body := []byte{dgStatusOK}
	if err != nil {
		text := oneLine(err.Error())
		if len(text) > dgMaxErrText {
			text = text[:dgMaxErrText]
		}
		body = append([]byte{dgStatusErr}, text...)
	}
	return dgEncode(dgRepMagic, typ, sid, seq, body)
}

// ---- client side ----------------------------------------------------------

// dgTransport carries protocol messages for one method.
type dgTransport interface {
	send(msg []byte) error
	// recv blocks for the next message that looks like a reply (or returns
	// an error). It is called from a single goroutine.
	recv() ([]byte, error)
	close() error
}

type dgParams struct {
	chunk  int           // payload bytes per DATA message
	window int           // DATA messages in flight at once (<= dgReorder)
	rto    time.Duration // initial and longest resend timeout; it adapts to the RTT
}

// dgMinRTO is the shortest resend timeout, so a fast LAN does not resend
// packets that are merely queued.
const dgMinRTO = 20 * time.Millisecond

type dgRep struct {
	typ    byte
	seq    uint32
	status byte
	text   string
	err    error // a receive error the transport reported instead of a reply
}

// sendDatagrams delivers the frame over tr and returns a summary for the
// results table.
func (a *attempt) sendDatagrams(tr dgTransport, p dgParams) (string, error) {
	defer tr.close()
	stop := closeOnDone(a, closerFunc(tr.close))
	defer stop()

	sid := randUint32()
	size := a.frame.size
	n := uint32((size + int64(p.chunk) - 1) / int64(p.chunk))

	done := make(chan struct{})
	defer close(done)
	replies := make(chan dgRep, 4*p.window+16)
	go func() {
		for {
			msg, err := tr.recv()
			var r dgRep
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				r.err = err
			} else {
				typ, rsid, seq, body, ok := dgParse(msg, dgRepMagic)
				if !ok || rsid != sid || len(body) < 1 {
					continue
				}
				r = dgRep{typ: typ, seq: seq, status: body[0], text: string(body[1:])}
			}
			select {
			case replies <- r:
			case <-done:
				return
			}
			if err != nil {
				// Avoid spinning on a socket that keeps failing.
				select {
				case <-time.After(50 * time.Millisecond):
				case <-done:
					return
				}
			}
		}
	}()

	sent, resent := 0, 0
	sendMsg := func(m []byte) error {
		sent++
		return tr.send(m)
	}
	est := newRTO(dgMinRTO, p.rto)

	// exchange sends msg until a reply of the same type and seq arrives,
	// resending on the current timeout. A zero limit waits as long as the
	// attempt's context allows (the idle guard and -timeout still apply).
	exchange := func(typ byte, seq uint32, msg []byte, limit time.Duration) (dgRep, error) {
		var deadline <-chan time.Time
		if limit > 0 {
			t := time.NewTimer(limit)
			defer t.Stop()
			deadline = t.C
		}
		var lastErr error
		for tries := 0; ; tries++ {
			if err := sendMsg(msg); err != nil && !a.connected.Load() {
				return dgRep{}, a.unreachable(err)
			}
			sentAt := time.Now()
			resend := time.NewTimer(est.rto)
		wait:
			for {
				select {
				case r := <-replies:
					if r.err != nil {
						if !a.connected.Load() && fatalBeforeContact(r.err) {
							resend.Stop()
							return dgRep{}, a.unreachable(r.err)
						}
						lastErr = r.err
						continue
					}
					if r.typ == typ && r.seq == seq {
						resend.Stop()
						if tries == 0 {
							est.sample(time.Since(sentAt))
						}
						return r, nil
					}
				case <-resend.C:
					resent++
					est.backoff()
					break wait
				case <-deadline:
					resend.Stop()
					if lastErr != nil && !isTimeout(lastErr) {
						return dgRep{}, fmt.Errorf("no usable answer within %s: %v", limit, a.httpOrPlain(lastErr))
					}
					return dgRep{}, a.unreachable(errDgNoAnswer)
				case <-a.ctx.Done():
					resend.Stop()
					return dgRep{}, a.ctx.Err()
				}
			}
		}
	}

	// INIT: the first answer is what shows the method gets through.
	body := binary.BigEndian.AppendUint64(nil, uint64(size))
	body = binary.BigEndian.AppendUint16(body, uint16(p.chunk))
	r, err := exchange(dgInit, 0, dgEncode(dgReqMagic, dgInit, sid, 0, body), a.opts.connectTimeout)
	if err != nil {
		return "", err
	}
	if r.status != dgStatusOK {
		return "", &refusedError{r.text}
	}
	a.connected.Store(true)
	a.guard.touch()
	a.logf("session %08x: %d chunks of up to %d bytes", sid, n, p.chunk)

	// DATA: a sliding window over the chunks. Only chunks within window of
	// the oldest unacknowledged one are sent, so the server never has to
	// buffer more than that.
	type flight struct {
		at     time.Time
		resent bool
	}
	acked := make([]bool, n)
	inflight := map[uint32]flight{}
	var base, next uint32 // oldest unacknowledged chunk; next chunk to send
	buf := make([]byte, p.chunk)
	sendChunk := func(seq uint32, again bool) error {
		m, err := a.frame.ReadAt(buf, int64(seq)*int64(p.chunk))
		if err != nil && err != io.EOF {
			return err
		}
		inflight[seq] = flight{at: time.Now(), resent: again}
		return sendMsg(dgEncode(dgReqMagic, dgData, sid, seq, buf[:m]))
	}
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for base < n {
		for next < n && next < base+uint32(p.window) {
			if err := sendChunk(next, false); err != nil {
				return "", fmt.Errorf("sending chunk %d: %w", next, err)
			}
			next++
		}
		select {
		case r := <-replies:
			if r.err != nil || r.typ != dgData || r.seq >= n {
				continue
			}
			if r.status != dgStatusOK {
				return "", &refusedError{r.text}
			}
			if !acked[r.seq] {
				acked[r.seq] = true
				if f, ok := inflight[r.seq]; ok && !f.resent {
					est.sample(time.Since(f.at))
				}
				delete(inflight, r.seq)
				a.guard.touch()
				for base < n && acked[base] {
					base++
				}
			}
		case now := <-tick.C:
			lost := false
			for seq, f := range inflight {
				if now.Sub(f.at) >= est.rto {
					resent++
					lost = true
					if err := sendChunk(seq, true); err != nil {
						return "", fmt.Errorf("sending chunk %d: %w", seq, err)
					}
				}
			}
			if lost {
				est.backoff() // once per round of losses, not once per packet
			}
		case <-a.ctx.Done():
			return "", a.ctx.Err()
		}
	}

	// FIN: the server finishes the transfer; its answer is the verdict.
	r, err = exchange(dgFin, n, dgEncode(dgReqMagic, dgFin, sid, n, nil), 0)
	if err != nil {
		return "", err
	}
	detail := fmt.Sprintf("%d chunks of %d B, %d packets sent, %d resent", n, p.chunk, sent, resent)
	if r.status != dgStatusOK {
		return detail, &refusedError{r.text}
	}
	return detail, nil
}

var errDgNoAnswer = timeoutError{}

// timeoutError is a net.Error reporting a timeout, for "nothing came back".
type timeoutError struct{}

func (timeoutError) Error() string   { return "no answer" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// fatalBeforeContact reports whether a receive error before the first reply
// shows the method cannot work, so there is no point waiting out the timeout.
func fatalBeforeContact(err error) bool {
	var ce *contactError
	return errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &ce)
}

// httpOrPlain strips the URL prefix from an HTTP client error.
func (a *attempt) httpOrPlain(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// rtTransport carries each message in a request/response exchange of its
// own (an HTTP request, say), several at once: one per message in flight.
type rtTransport struct {
	ctx     context.Context
	cancel  context.CancelFunc
	rt      func(ctx context.Context, msg []byte) ([]byte, error)
	replies chan rtReply
}

type rtReply struct {
	msg []byte
	err error
}

func newRTTransport(parent context.Context, rt func(ctx context.Context, msg []byte) ([]byte, error)) *rtTransport {
	ctx, cancel := context.WithCancel(parent)
	return &rtTransport{ctx: ctx, cancel: cancel, rt: rt, replies: make(chan rtReply, 64)}
}

func (t *rtTransport) send(msg []byte) error {
	go func() {
		b, err := t.rt(t.ctx, msg)
		select {
		case t.replies <- rtReply{b, err}:
		case <-t.ctx.Done():
		}
	}()
	return nil
}

func (t *rtTransport) recv() ([]byte, error) {
	select {
	case r := <-t.replies:
		return r.msg, r.err
	case <-t.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (t *rtTransport) close() error { t.cancel(); return nil }

// ---- server side ----------------------------------------------------------

// dgServer tracks the transfers in progress on one datagram method.
type dgServer struct {
	s      *Server
	method string

	mu       sync.Mutex
	sessions map[uint32]*dgSession
	quit     chan struct{}
}

type dgSession struct {
	size    int64
	chunk   int
	n       uint32
	next    uint32            // next chunk to hand to the receiver
	pending map[uint32][]byte // chunks that arrived early
	pw      *io.PipeWriter
	done    chan error // the receiver's result

	failed   error // the receiver stopped early; every later message gets this
	finished bool  // FIN processed; result is the verdict
	result   error
	last     time.Time
}

func newDgServer(s *Server, method string) *dgServer {
	d := &dgServer{s: s, method: method, sessions: map[uint32]*dgSession{}, quit: make(chan struct{})}
	go d.reap()
	return d
}

func (d *dgServer) close() { close(d.quit) }

// reap drops sessions whose client has gone quiet, and finished sessions
// once their client has had time to collect the verdict.
func (d *dgServer) reap() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-d.quit:
			d.mu.Lock()
			for id, sess := range d.sessions {
				sess.pw.CloseWithError(errors.New("server shutting down"))
				delete(d.sessions, id)
			}
			d.mu.Unlock()
			return
		case now := <-t.C:
			d.mu.Lock()
			for id, sess := range d.sessions {
				idle := now.Sub(sess.last)
				switch {
				case sess.finished || sess.failed != nil:
					if idle > time.Minute {
						delete(d.sessions, id)
					}
				case idle > serverIdleTimeout:
					sess.pw.CloseWithError(fmt.Errorf("client went silent for %s", serverIdleTimeout))
					delete(d.sessions, id)
				}
			}
			d.mu.Unlock()
		}
	}
}

// handle processes one request message and returns the reply to send back,
// or nil to stay silent (not ours, or a chunk too far ahead to buffer).
func (d *dgServer) handle(msg []byte, remote string) []byte {
	typ, sid, seq, body, ok := dgParse(msg, dgReqMagic)
	if !ok {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	sess := d.sessions[sid]

	switch typ {
	case dgInit:
		if sess == nil {
			var err error
			if sess, err = d.start(sid, body, remote); err != nil {
				return dgReply(dgInit, sid, 0, err)
			}
			d.s.debugf(d.method, "session %08x from %s: %d bytes in %d chunks", sid, remote, sess.size, sess.n)
		}
		sess.last = time.Now()
		return dgReply(dgInit, sid, 0, nil)

	case dgData:
		if sess == nil {
			return dgReply(dgData, sid, seq, errors.New("unknown session (server restarted?)"))
		}
		sess.last = time.Now()
		switch {
		case sess.failed != nil:
			return dgReply(dgData, sid, seq, sess.failed)
		case sess.finished || seq < sess.next:
			return dgReply(dgData, sid, seq, nil) // a resend of something we have
		case seq >= sess.n:
			return dgReply(dgData, sid, seq, fmt.Errorf("chunk %d is past the end (%d chunks)", seq, sess.n))
		case len(body) != sess.chunkLen(seq):
			return dgReply(dgData, sid, seq, fmt.Errorf("chunk %d has %d bytes, want %d", seq, len(body), sess.chunkLen(seq)))
		case seq >= sess.next+dgReorder:
			return nil // too far ahead; the client will send it again
		case seq > sess.next:
			if _, have := sess.pending[seq]; !have {
				sess.pending[seq] = append([]byte(nil), body...)
			}
			return dgReply(dgData, sid, seq, nil)
		}
		// seq == next: hand it, and anything queued behind it, to the receiver.
		if err := sess.write(body); err != nil {
			return dgReply(dgData, sid, seq, err)
		}
		for {
			b, have := sess.pending[sess.next]
			if !have {
				break
			}
			delete(sess.pending, sess.next)
			if err := sess.write(b); err != nil {
				return dgReply(dgData, sid, seq, err)
			}
		}
		return dgReply(dgData, sid, seq, nil)

	case dgFin:
		if sess == nil {
			return dgReply(dgFin, sid, seq, errors.New("unknown session (server restarted?)"))
		}
		sess.last = time.Now()
		if sess.failed != nil {
			return dgReply(dgFin, sid, seq, sess.failed)
		}
		if !sess.finished {
			if sess.next < sess.n {
				return dgReply(dgFin, sid, seq, fmt.Errorf("missing chunk %d of %d", sess.next, sess.n))
			}
			// Every chunk is in: end the stream and wait for the verdict.
			// The receiver has already read and hashed everything, so this
			// is quick (a rename, at most).
			sess.pw.Close()
			sess.result = <-sess.done
			sess.finished = true
		}
		return dgReply(dgFin, sid, seq, sess.result)
	}
	return nil
}

// start creates a session from an INIT body and starts its receiver.
func (d *dgServer) start(sid uint32, body []byte, remote string) (*dgSession, error) {
	if len(body) < 10 {
		return nil, errors.New("bad INIT")
	}
	size := int64(binary.BigEndian.Uint64(body))
	chunk := int(binary.BigEndian.Uint16(body[8:]))
	if size <= 0 || chunk <= 0 {
		return nil, errors.New("bad INIT: size and chunk size must be positive")
	}
	nchunks := (size + int64(chunk) - 1) / int64(chunk)
	if nchunks > 1<<31 {
		return nil, errors.New("bad INIT: too many chunks")
	}
	if len(d.sessions) >= dgMaxSessions {
		return nil, errors.New("server busy: too many transfers in progress")
	}
	pr, pw := io.Pipe()
	sess := &dgSession{
		size: size, chunk: chunk, n: uint32(nchunks),
		pending: map[uint32][]byte{},
		pw:      pw,
		done:    make(chan error, 1),
		last:    time.Now(),
	}
	go func() {
		err := d.s.receive(d.method, remote, pr)
		if err == nil {
			_, _ = io.Copy(io.Discard, pr) // wait for the end of the stream
			pr.Close()
		} else {
			pr.CloseWithError(err) // writers now get err: the reason to report
		}
		sess.done <- err
	}()
	d.sessions[sid] = sess
	return sess, nil
}

func (sess *dgSession) chunkLen(seq uint32) int {
	if seq == sess.n-1 {
		return int(sess.size - int64(sess.n-1)*int64(sess.chunk))
	}
	return sess.chunk
}

// write passes the next in-order chunk to the receiver. If the receiver has
// stopped (bad header, SHA-256 mismatch, disk error), its error comes back
// and is reported for the rest of the session.
func (sess *dgSession) write(b []byte) error {
	if _, err := sess.pw.Write(b); err != nil {
		sess.failed = err
		return err
	}
	sess.next++
	return nil
}
