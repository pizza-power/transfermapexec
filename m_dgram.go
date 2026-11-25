package main

// Datagram carriers for the protocol in dgram.go. A dgCodec wraps its
// messages in another protocol's packets; raw udp uses none, ntp, syslog and
// snmp (m_monitor.go) use theirs. icmp is here too: echo requests and
// replies, over IPv4 or IPv6.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// dgCodec carries the datagram protocol inside another protocol's UDP
// packets. A nil codec sends the messages as they are.
type dgCodec interface {
	// wrapRequest builds the client's packet for msg.
	wrapRequest(msg []byte) []byte
	// unwrapRequest extracts the message from a client packet, or returns
	// nil for a packet that is not one of ours.
	unwrapRequest(pkt []byte) []byte
	// wrapReply builds the server's answer to request pkt, carrying reply.
	wrapReply(pkt, reply []byte) []byte
	// unwrapReply extracts the message from a server packet, or nil.
	unwrapReply(pkt []byte) []byte
}

type udpTransport struct {
	c     net.Conn
	codec dgCodec
}

func (t *udpTransport) close() error { return t.c.Close() }

func (t *udpTransport) send(m []byte) error {
	if t.codec != nil {
		m = t.codec.wrapRequest(m)
	}
	_, err := t.c.Write(m)
	return err
}

func (t *udpTransport) recv() ([]byte, error) {
	buf := make([]byte, 65535)
	for {
		n, err := t.c.Read(buf)
		if err != nil {
			return nil, err
		}
		if t.codec == nil {
			return buf[:n], nil
		}
		if msg := t.codec.unwrapReply(buf[:n]); msg != nil {
			return msg, nil
		}
	}
}

// sendDatagramsUDP runs the datagram protocol over UDP to the method's port.
func (a *attempt) sendDatagramsUDP(codec dgCodec, p dgParams) (string, error) {
	// A connected socket, so an ICMP "port unreachable" comes back as
	// "connection refused" instead of silence.
	c, err := a.dial("udp")
	if err != nil {
		return "", err
	}
	return a.sendDatagrams(&udpTransport{c, codec}, p)
}

// serveDatagramsUDP answers the datagram protocol on a UDP port.
func serveDatagramsUDP(s *Server, addr, method string, codec dgCodec) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	d := newDgServer(s, method)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			pkt := buf[:n]
			msg := pkt
			if codec != nil {
				if msg = codec.unwrapRequest(pkt); msg == nil {
					continue
				}
			}
			reply := d.handle(msg, from.String())
			if reply == nil {
				continue
			}
			if codec != nil {
				reply = codec.wrapReply(pkt, reply)
			}
			_, _ = pc.WriteTo(reply, from)
		}
	}()
	return closerFunc(func() error { d.close(); return pc.Close() }), nil
}

// ---- udp ------------------------------------------------------------------

func sendUDP(a *attempt) (string, error) {
	// 1200-byte chunks keep every datagram under the smallest IPv6 MTU.
	return a.sendDatagramsUDP(nil, dgParams{chunk: 1200, window: 64, rto: 300 * time.Millisecond})
}

func serveUDP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return serveDatagramsUDP(s, addr, "udp", nil)
}

// ---- icmp -----------------------------------------------------------------
//
// Each message rides in the payload of an echo request (ICMP, or ICMPv6 for
// an IPv6 target). The server answers with its own echo reply carrying its
// protocol reply. The server's kernel also answers every ping, echoing the
// request back; the client tells the two apart by the magic at the start of
// the payload.

// icmpFamily holds what differs between ICMP and ICMPv6.
type icmpFamily struct {
	proto        int // IANA protocol number, for parsing
	request      icmp.Type
	reply        icmp.Type
	dgram, raw   string // ListenPacket networks: unprivileged and raw
	wildcard     string
	name         string
	unprivileged string // how to allow unprivileged pings on Linux
}

var (
	icmp4 = icmpFamily{1, ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, "udp4", "ip4:icmp", "0.0.0.0", "ICMP", "sysctl net.ipv4.ping_group_range"}
	icmp6 = icmpFamily{58, ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, "udp6", "ip6:ipv6-icmp", "::", "ICMPv6", "sysctl net.ipv4.ping_group_range (it covers IPv6 too)"}
)

type icmpTransport struct {
	fam        icmpFamily
	c          *icmp.PacketConn
	dst        net.Addr
	ip         net.IP
	id         int
	seq        int
	privileged bool
}

func (t *icmpTransport) close() error { return t.c.Close() }

func (t *icmpTransport) send(msg []byte) error {
	t.seq++
	m := icmp.Message{Type: t.fam.request, Body: &icmp.Echo{ID: t.id, Seq: t.seq & 0xffff, Data: msg}}
	// For ICMPv6 the kernel fills in the checksum (it covers a pseudo-header).
	b, err := m.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = t.c.WriteTo(b, t.dst)
	return err
}

func (t *icmpTransport) recv() ([]byte, error) {
	buf := make([]byte, 2048)
	for {
		n, peer, err := t.c.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		m, err := icmp.ParseMessage(t.fam.proto, buf[:n])
		if err != nil || m.Type != t.fam.reply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok || !addrIP(peer).Equal(t.ip) {
			continue
		}
		// An unprivileged socket only sees its own replies (the kernel may
		// rewrite the ID); a raw socket sees every reply on the host.
		if t.privileged && echo.ID != t.id {
			continue
		}
		if len(echo.Data) >= 2 && string(echo.Data[:2]) == dgRepMagic {
			return echo.Data, nil
		}
	}
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func sendICMP(a *attempt) (string, error) {
	fam := icmp4
	if a.tgt.v6() {
		fam = icmp6
	}
	t := &icmpTransport{fam: fam, ip: a.tgt.ip, id: int(randUint32() & 0xffff)}
	// Unprivileged ICMP sockets work on macOS, and on Linux when
	// net.ipv4.ping_group_range includes the user; otherwise fall back to a
	// raw socket, which needs root (or admin on Windows).
	var err error
	mode := "unprivileged " + fam.name + " socket"
	if t.c, err = icmp.ListenPacket(fam.dgram, fam.wildcard); err == nil {
		t.dst = &net.UDPAddr{IP: a.tgt.ip}
	} else if t.c, err = icmp.ListenPacket(fam.raw, fam.wildcard); err == nil {
		t.dst, t.privileged, mode = &net.IPAddr{IP: a.tgt.ip}, true, "raw "+fam.name+" socket"
	} else {
		return "", fmt.Errorf("cannot open an %s socket (run as root/admin, or on Linux allow unprivileged pings with %s): %w", fam.name, fam.unprivileged, err)
	}
	detail, err := a.sendDatagrams(t, dgParams{chunk: 1000, window: 32, rto: 300 * time.Millisecond})
	if detail != "" {
		detail = mode + ", " + detail
	}
	if err != nil && !a.connected.Load() && a.ctx.Err() == nil {
		// Plain pings may well be answered (by the server's kernel); what
		// is missing is an answer from transfermapexec itself.
		err = fmt.Errorf("%w; note the icmp server must run as root on Linux (macOS never hands pings to programs)", err)
	}
	return detail, err
}

// serveICMP answers pings over IPv4 and IPv6. Either family may be missing
// (no IPv6 on the host); only both missing is an error.
func serveICMP(s *Server, bind string, _ methodSet) (io.Closer, error) {
	var closers []io.Closer
	var errs []error
	for _, fam := range []icmpFamily{icmp4, icmp6} {
		addr := fam.wildcard
		if ip := net.ParseIP(bind); ip != nil {
			if (ip.To4() != nil) != (fam.proto == 1) {
				continue // -bind picks the other family
			}
			addr = bind
		}
		c, err := icmp.ListenPacket(fam.raw, addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", fam.name, err))
			continue
		}
		d := newDgServer(s, "icmp")
		go s.serveICMPConn(c, d, fam)
		closers = append(closers, closerFunc(func() error { d.close(); return c.Close() }))
	}
	if len(closers) == 0 {
		var msgs []string
		for _, err := range errs {
			msgs = append(msgs, err.Error())
		}
		return nil, fmt.Errorf("%s (receiving pings needs root, or CAP_NET_RAW on Linux)", strings.Join(msgs, "; "))
	}
	for _, err := range errs {
		s.logf("icmp", "note: %v", err)
	}
	return closerFunc(func() error {
		for _, c := range closers {
			c.Close()
		}
		return nil
	}), nil
}

func (s *Server) serveICMPConn(c *icmp.PacketConn, d *dgServer, fam icmpFamily) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m, err := icmp.ParseMessage(fam.proto, buf[:n])
		if err != nil || m.Type != fam.request {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		reply := d.handle(echo.Data, peer.String())
		if reply == nil {
			continue
		}
		rm := icmp.Message{Type: fam.reply, Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: reply}}
		if b, err := rm.Marshal(nil); err == nil {
			_, _ = c.WriteTo(b, peer)
		}
	}
}
