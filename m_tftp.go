package main

// The tftp method uploads the frame with a TFTP write request (RFC 1350),
// octet mode, asking for a larger block size (RFC 2348) and announcing the
// size (RFC 2349). Like any TFTP server, the server answers from a new port
// for each transfer, which is worth testing in its own right: stateful
// firewalls and NAT often break exactly that.
//
// The server holds back its ACK of the final block until the frame has been
// checked and stored, then sends that ACK, or an ERROR with the reason: the
// verdict.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	tftpRRQ   = 1
	tftpWRQ   = 2
	tftpDATA  = 3
	tftpACK   = 4
	tftpERROR = 5
	tftpOACK  = 6

	// tftpBlksize is what the client asks for: a block that, with IPv4, UDP
	// and TFTP headers, fits a 1500-byte MTU.
	tftpBlksize = 1428
	tftpRTO     = 500 * time.Millisecond
)

// tftpStrings builds a packet of opcode followed by NUL-terminated strings
// (RRQ, WRQ, OACK).
func tftpStrings(op uint16, parts ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, op)
	for _, p := range parts {
		b = append(b, p...)
		b = append(b, 0)
	}
	return b
}

func tftpBlock(op, block uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, op)
	b = binary.BigEndian.AppendUint16(b, block)
	return append(b, data...)
}

// tftpErrorPacket builds an ERROR packet: opcode, error code, message, NUL.
func tftpErrorPacket(code uint16, msg string) []byte {
	b := binary.BigEndian.AppendUint16(nil, tftpERROR)
	b = binary.BigEndian.AppendUint16(b, code)
	b = append(b, oneLine(msg)...)
	return append(b, 0)
}

func tftpErrorText(pkt []byte) string {
	if len(pkt) < 4 {
		return "TFTP error"
	}
	code := binary.BigEndian.Uint16(pkt[2:4])
	msg := strings.TrimRight(string(pkt[4:]), "\x00")
	return fmt.Sprintf("TFTP error %d: %s", code, msg)
}

// tftpOptions parses option/value pairs (keys lowercased).
func tftpOptions(fields []string) map[string]string {
	opts := map[string]string{}
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] != "" {
			opts[strings.ToLower(fields[i])] = fields[i+1]
		}
	}
	return opts
}

func sendTFTP(a *attempt) (string, error) {
	raddr, err := net.ResolveUDPAddr("udp", a.addr)
	if err != nil {
		return "", err
	}
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return "", err
	}
	defer c.Close()
	stop := closeOnDone(a, c)
	defer stop()

	name := a.uploadName()
	size := a.frame.size

	var tid *net.UDPAddr // the server's port for this transfer
	buf := make([]byte, 65536)
	// read returns the next packet from the server before deadline. Until
	// the transfer port is known, any port on the server's host will do.
	read := func(deadline time.Time) (uint16, []byte, *net.UDPAddr, error) {
		_ = c.SetReadDeadline(deadline)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return 0, nil, nil, err
			}
			if n < 4 {
				continue
			}
			if tid != nil && (from.Port != tid.Port || !from.IP.Equal(tid.IP)) {
				_, _ = c.WriteToUDP(tftpErrorPacket(5, "unknown transfer ID"), from)
				continue
			}
			if tid == nil && !from.IP.Equal(raddr.IP) {
				a.logf("first reply came from %s, not %s", from.IP, raddr.IP)
			}
			return binary.BigEndian.Uint16(buf[:2]), buf[:n], from, nil
		}
	}

	// Write request, resent until the server answers (OACK with the options
	// it accepted, or ACK 0 if it ignores options) or -connect-timeout.
	wrq := tftpStrings(tftpWRQ, name, "octet", "blksize", strconv.Itoa(tftpBlksize), "tsize", strconv.FormatInt(size, 10))
	blksize := 512
	contact := time.Now().Add(a.opts.connectTimeout)
	sent, resent := 0, 0
handshake:
	for {
		if time.Now().After(contact) {
			return "", a.unreachable(errDgNoAnswer)
		}
		if _, err := c.WriteToUDP(wrq, raddr); err != nil {
			return "", a.unreachable(err)
		}
		sent++
		wait := time.Now().Add(tftpRTO)
		if contact.Before(wait) {
			wait = contact
		}
		for {
			op, pkt, from, err := read(wait)
			if err != nil {
				if isTimeout(err) && a.ctx.Err() == nil {
					break // resend
				}
				return "", a.unreachable(err)
			}
			switch op {
			case tftpOACK:
				opts := tftpOptions(strings.Split(string(pkt[2:]), "\x00"))
				if v, ok := opts["blksize"]; ok {
					if bs, err := strconv.Atoi(v); err == nil && bs >= 8 && bs <= tftpBlksize {
						blksize = bs
					}
				}
				tid = from
				break handshake
			case tftpACK:
				if binary.BigEndian.Uint16(pkt[2:4]) == 0 {
					tid = from
					break handshake
				}
			case tftpERROR:
				return "", &refusedError{tftpErrorText(pkt)}
			}
		}
	}
	a.connected.Store(true)
	a.guard.touch()
	a.logf("transfer port %d, blksize %d", tid.Port, blksize)

	// Data, one block at a time, each resent until it is acknowledged. The
	// last block is shorter than blksize (empty if the size divides evenly);
	// its ACK, which the server sends once the data is stored, is the
	// verdict. Block numbers wrap around after 65535.
	nblocks := size/int64(blksize) + 1
	data := make([]byte, blksize)
	est := newRTO(dgMinRTO, tftpRTO)
	for i := int64(1); i <= nblocks; i++ {
		off := (i - 1) * int64(blksize)
		n, err := a.frame.ReadAt(data[:min(int64(blksize), size-off)], off)
		if err != nil && err != io.EOF {
			return "", err
		}
		block := uint16(i)
		pkt := tftpBlock(tftpDATA, block, data[:n])
	resend:
		for tries := 0; ; tries++ {
			if _, err := c.WriteToUDP(pkt, tid); err != nil {
				return "", fmt.Errorf("sending block %d: %w", i, err)
			}
			sent++
			sentAt := time.Now()
			// Wait out the whole resend interval: answering a stray
			// duplicate ACK with another send would double the traffic.
			wait := sentAt.Add(est.rto)
			if i == nblocks {
				// The final ACK comes once the server has stored the file.
				wait = sentAt.Add(tftpRTO)
			}
			for {
				op, reply, _, err := read(wait)
				if err != nil {
					if isTimeout(err) && a.ctx.Err() == nil {
						resent++
						est.backoff()
						continue resend
					}
					return "", err
				}
				switch op {
				case tftpACK:
					if binary.BigEndian.Uint16(reply[2:4]) == block {
						if tries == 0 {
							est.sample(time.Since(sentAt))
						}
						a.guard.touch()
						break resend
					}
				case tftpERROR:
					return "", &refusedError{tftpErrorText(reply)}
				}
			}
		}
	}
	return fmt.Sprintf("blksize %d, %d blocks, %d packets sent, %d resent", blksize, nblocks, sent, resent), nil
}

func serveTFTP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if n < 4 {
				continue
			}
			switch binary.BigEndian.Uint16(buf[:2]) {
			case tftpWRQ:
				go s.tftpWrite(ua.IP, from, append([]byte(nil), buf[2:n]...))
			case tftpRRQ:
				_, _ = pc.WriteToUDP(tftpErrorPacket(2, "this server only accepts uploads (WRQ)"), from)
			}
		}
	}()
	return pc, nil
}

// tftpWrite runs one upload on its own port, as TFTP does.
func (s *Server) tftpWrite(bindIP net.IP, client *net.UDPAddr, req []byte) {
	remote := client.String()
	fields := strings.Split(string(req), "\x00")
	if len(fields) < 2 {
		return
	}
	filename, mode := fields[0], strings.ToLower(fields[1])

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		s.logf("tftp", "cannot open a transfer port for %s: %v", remote, err)
		return
	}
	defer conn.Close()
	send := func(p []byte) { _, _ = conn.WriteToUDP(p, client) }

	if mode != "octet" {
		send(tftpErrorPacket(0, "only octet mode is supported"))
		return
	}
	s.debugf("tftp", "WRQ %q from %s (transfer port %d)", filename, remote, conn.LocalAddr().(*net.UDPAddr).Port)

	// Accept the options we understand and say so in an OACK; without
	// options, ACK block 0 as plain RFC 1350 does.
	opts := tftpOptions(fields[2:])
	blksize := 512
	var oack []string
	if v, ok := opts["blksize"]; ok {
		if bs, err := strconv.Atoi(v); err == nil && bs >= 8 {
			blksize = min(bs, 65464)
			oack = append(oack, "blksize", strconv.Itoa(blksize))
		}
	}
	if v, ok := opts["tsize"]; ok {
		oack = append(oack, "tsize", v)
	}
	lastSent := tftpBlock(tftpACK, 0, nil)
	if len(oack) > 0 {
		lastSent = tftpStrings(tftpOACK, oack...)
	}

	// Blocks arrive in order, so they stream straight into the receiver.
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := s.receive("tftp", remote, pr)
		if err == nil {
			_, _ = io.Copy(io.Discard, pr)
			pr.Close()
		} else {
			pr.CloseWithError(err)
		}
		done <- err
	}()
	abort := func(err error) {
		pw.CloseWithError(err)
		<-done
	}

	send(lastSent)
	expect := uint16(1)
	lastProgress := time.Now()
	buf := make([]byte, blksize+4)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * tftpRTO))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !isTimeout(err) {
				abort(err)
				return
			}
			if time.Since(lastProgress) > serverIdleTimeout {
				abort(fmt.Errorf("client went silent for %s", serverIdleTimeout))
				return
			}
			send(lastSent) // our last packet may have been lost
			continue
		}
		if from.Port != client.Port || !from.IP.Equal(client.IP) {
			_, _ = conn.WriteToUDP(tftpErrorPacket(5, "unknown transfer ID"), from)
			continue
		}
		if n < 4 {
			continue
		}
		switch binary.BigEndian.Uint16(buf[:2]) {
		case tftpDATA:
		case tftpERROR:
			abort(errors.New("client aborted: " + tftpErrorText(buf[:n])))
			return
		default:
			continue
		}
		block := binary.BigEndian.Uint16(buf[2:4])
		if block != expect {
			if block == expect-1 {
				send(lastSent) // our ACK was lost
			}
			continue
		}
		data := buf[4:n]
		lastProgress = time.Now()
		if _, err := pw.Write(data); err != nil {
			// The receiver stopped early (bad header, ...): pass on why.
			send(tftpErrorPacket(0, (<-done).Error()))
			return
		}
		if len(data) < blksize {
			// Final block: finish the transfer, then answer with the verdict.
			pw.Close()
			final := tftpBlock(tftpACK, block, nil)
			if err := <-done; err != nil {
				final = tftpErrorPacket(0, err.Error())
			}
			send(final)
			s.tftpLinger(conn, client, block, final)
			return
		}
		lastSent = tftpBlock(tftpACK, block, nil)
		send(lastSent)
		expect++
	}
}

// tftpLinger answers resends of the final block for a few seconds, in case
// the final ACK was lost.
func (s *Server) tftpLinger(conn *net.UDPConn, client *net.UDPAddr, block uint16, final []byte) {
	buf := make([]byte, 65535)
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		_ = conn.SetReadDeadline(until)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n >= 4 && from.Port == client.Port && from.IP.Equal(client.IP) &&
			binary.BigEndian.Uint16(buf[:2]) == tftpDATA && binary.BigEndian.Uint16(buf[2:4]) == block {
			_, _ = conn.WriteToUDP(final, client)
		}
	}
}
