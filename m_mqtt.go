package main

// The mqtt method talks MQTT 3.1.1 to the server acting as a broker, the way
// an IoT device reports in: CONNECT, SUBSCRIBE to its own result topic, then
// PUBLISH the frame in chunks at QoS 1 to transfermapexec/<client-id>/upload,
// each acknowledged with PUBACK. Once the server has checked and stored the
// data, it publishes "OK" or "ERR <reason>" to transfermapexec/<client-id>/result:
// the verdict.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	mqttConnect    = 1
	mqttConnack    = 2
	mqttPublish    = 3
	mqttPuback     = 4
	mqttSubscribe  = 8
	mqttSuback     = 9
	mqttPingreq    = 12
	mqttPingresp   = 13
	mqttDisconnect = 14

	mqttChunk    = 32 << 10
	mqttInflight = 32
	mqttMaxPkt   = 1 << 20
)

func mqttStr(s string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(s))), s...)
}

func mqttPacket(typ, flags byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	b := []byte{typ<<4 | flags}
	for n := len(body); ; {
		c := byte(n % 128)
		n /= 128
		if n > 0 {
			c |= 0x80
		}
		b = append(b, c)
		if n == 0 {
			break
		}
	}
	return append(b, body...)
}

// mqttRead reads one control packet.
func mqttRead(r *bufio.Reader) (typ, flags byte, body []byte, err error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	n, mult := 0, 1
	for i := 0; ; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		n += int(c&0x7f) * mult
		if c&0x80 == 0 {
			break
		}
		if mult *= 128; i == 3 {
			return 0, 0, nil, errors.New("bad MQTT remaining length")
		}
	}
	if n > mqttMaxPkt {
		return 0, 0, nil, fmt.Errorf("MQTT packet of %d bytes is too large", n)
	}
	body = make([]byte, n)
	_, err = io.ReadFull(r, body)
	return first >> 4, first & 0x0f, body, err
}

// mqttParseStr splits a length-prefixed string off b.
func mqttParseStr(b []byte) (string, []byte, error) {
	if len(b) < 2 || len(b) < 2+int(binary.BigEndian.Uint16(b)) {
		return "", nil, errors.New("short MQTT string")
	}
	n := 2 + int(binary.BigEndian.Uint16(b))
	return string(b[2:n]), b[n:], nil
}

func sendMQTT(a *attempt) (string, error) {
	c, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer c.Close()
	stop := closeOnDone(a, c)
	defer stop()
	r := bufio.NewReader(c)

	cid := fmt.Sprintf("mt-%08x", randUint32())
	topic := "transfermapexec/" + cid
	err = a.handshake(c, func() error {
		connect := mqttPacket(mqttConnect, 0, mqttStr("MQTT"), []byte{4, 0x02, 0, 60}, mqttStr(cid)) // v3.1.1, clean session, keep-alive 60 s
		if _, err := c.Write(connect); err != nil {
			return err
		}
		typ, _, body, err := mqttRead(r)
		switch {
		case err != nil:
			return err
		case typ != mqttConnack || len(body) < 2:
			return fmt.Errorf("expected CONNACK, got packet type %d", typ)
		case body[1] != 0:
			return &refusedError{fmt.Sprintf("CONNACK return code %d", body[1])}
		}
		subscribe := mqttPacket(mqttSubscribe, 0x02, []byte{0, 1}, mqttStr(topic+"/result"), []byte{1})
		if _, err := c.Write(subscribe); err != nil {
			return err
		}
		if typ, _, _, err = mqttRead(r); err == nil && typ != mqttSuback {
			err = fmt.Errorf("expected SUBACK, got packet type %d", typ)
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("MQTT connect: %w", err)
	}

	// The reader takes PUBACKs and the result; writes from both sides share
	// the connection under a lock.
	var wmu sync.Mutex
	write := func(p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_, err := c.Write(p)
		return err
	}
	slots := make(chan struct{}, mqttInflight)
	verdict := make(chan string, 1)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, flags, body, err := mqttRead(r)
			if err != nil {
				readErr <- err
				return
			}
			switch typ {
			case mqttPuback:
				select {
				case <-slots:
				default:
				}
				a.guard.touch()
			case mqttPublish:
				t, rest, err := mqttParseStr(body)
				if err != nil {
					continue
				}
				if (flags>>1)&3 > 0 && len(rest) >= 2 {
					_ = write(mqttPacket(mqttPuback, 0, rest[:2]))
					rest = rest[2:]
				}
				if t == topic+"/result" {
					verdict <- string(rest)
					return
				}
			}
		}
	}()

	src := a.source()
	buf := make([]byte, mqttChunk)
	pid := uint16(1)
	published := 0
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			select {
			case slots <- struct{}{}:
			case v := <-verdict: // the server gave up early
				return "", verdictText(v)
			case err := <-readErr:
				return "", fmt.Errorf("connection lost: %w", err)
			case <-a.ctx.Done():
				return "", a.ctx.Err()
			}
			if pid++; pid == 0 {
				pid = 2
			}
			p := mqttPacket(mqttPublish, 1<<1, mqttStr(topic+"/upload"), binary.BigEndian.AppendUint16(nil, pid), buf[:n])
			if err := write(p); err != nil {
				return "", fmt.Errorf("sending failed: %w", err)
			}
			published++
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}

	select {
	case v := <-verdict:
		_ = write(mqttPacket(mqttDisconnect, 0))
		return fmt.Sprintf("%d PUBLISH (QoS 1)", published), verdictText(v)
	case err := <-readErr:
		return "", fmt.Errorf("no delivery confirmation: %w", err)
	case <-a.ctx.Done():
		return "", a.ctx.Err()
	}
}

func serveMQTT(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.serveMQTTConn)
	return ln, nil
}

func (s *Server) serveMQTTConn(raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr().String()
	c := &idleConn{raw, serverIdleTimeout}
	r := bufio.NewReader(c)
	var wmu sync.Mutex
	write := func(p []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = c.Write(p)
	}

	typ, _, body, err := mqttRead(r)
	if err != nil || typ != mqttConnect {
		s.debugf("mqtt", "no CONNECT from %s", remote)
		return
	}
	proto, rest, err := mqttParseStr(body)
	if err != nil || (proto != "MQTT" && proto != "MQIsdp") || len(rest) < 4 {
		write(mqttPacket(mqttConnack, 0, []byte{0, 1})) // unacceptable protocol version
		return
	}
	cid, _, _ := mqttParseStr(rest[4:])
	write(mqttPacket(mqttConnack, 0, []byte{0, 0}))
	s.debugf("mqtt", "client %q connected from %s", cid, remote)

	var (
		pw     *io.PipeWriter
		result string
	)
	defer func() {
		if pw != nil {
			pw.CloseWithError(errors.New("client disconnected"))
		}
	}()
	for {
		typ, flags, body, err := mqttRead(r)
		if err != nil {
			return
		}
		switch typ {
		case mqttPublish:
			topic, rest, err := mqttParseStr(body)
			if err != nil {
				return
			}
			qos := (flags >> 1) & 3
			if qos == 2 {
				return // not supported
			}
			if qos == 1 {
				if len(rest) < 2 {
					return
				}
				write(mqttPacket(mqttPuback, 0, rest[:2]))
				rest = rest[2:]
			}
			if !strings.HasSuffix(topic, "/upload") {
				continue
			}
			if pw == nil {
				result = strings.TrimSuffix(topic, "/upload") + "/result"
				var pr *io.PipeReader
				pr, pw = io.Pipe()
				go func(result string) {
					verdict := "OK"
					if err := s.receive("mqtt", remote, pr); err != nil {
						verdict = "ERR " + oneLine(err.Error())
						pr.CloseWithError(err)
					} else {
						pr.Close()
					}
					write(mqttPacket(mqttPublish, 0, mqttStr(result), []byte(verdict)))
				}(result)
			}
			_, _ = pw.Write(rest) // after the receiver stops, the rest is dropped
		case mqttSubscribe:
			if len(body) < 2 {
				return
			}
			var granted []byte
			for rest := body[2:]; len(rest) > 0; {
				_, r2, err := mqttParseStr(rest)
				if err != nil || len(r2) < 1 {
					break
				}
				granted = append(granted, 1)
				rest = r2[1:]
			}
			write(mqttPacket(mqttSuback, 0, body[:2], granted))
		case mqttPingreq:
			write(mqttPacket(mqttPingresp, 0))
		case mqttDisconnect:
			time.Sleep(10 * time.Millisecond)
			return
		}
	}
}
