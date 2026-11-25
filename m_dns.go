package main

// DNS tunnelling, four ways: dns (UDP), dns-tcp (TCP), dot (DNS-over-TLS,
// RFC 7858) and doh (DNS-over-HTTPS, RFC 8484). All four carry the datagram
// protocol the same way:
//
// Each message is base32-encoded (case-insensitive, so it survives resolvers
// that randomize case) into the labels of a TXT query under -dns-domain:
//
//	<63 chars>.<63 chars>.<63 chars>.<rest>.mt.test.
//
// The server answers with a TXT record holding its base64-encoded reply.
// With -dns-server, the dns method's queries go through a resolver, which
// works when that resolver forwards the domain to the server (a delegation,
// or a forward zone).

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dohPath    = "/dns-query"
	dohType    = "application/dns-message"
	alpnDoT    = "dot"
	dnsTimeout = 500 * time.Millisecond
)

var dnsB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsChunkSize is the payload per query that fits in a DNS name (at most 253
// characters) under domain.
func dnsChunkSize(domain string) int {
	avail := 253 - len(domain) - 1 // characters for data labels and their dots
	c := avail
	for c > 0 && c+(c+62)/63-1 > avail {
		c--
	}
	return c*5/8 - dgHdrLen
}

func dnsEncodeName(msg []byte, domain string) string {
	enc := strings.ToLower(dnsB32.EncodeToString(msg))
	var b strings.Builder
	for len(enc) > 63 {
		b.WriteString(enc[:63])
		b.WriteByte('.')
		enc = enc[63:]
	}
	b.WriteString(enc)
	b.WriteByte('.')
	b.WriteString(domain)
	b.WriteByte('.')
	return b.String()
}

// dnsQuery builds a TXT query carrying msg.
func dnsQuery(msg []byte, domain string, id uint16) ([]byte, error) {
	name, err := dnsmessage.NewName(dnsEncodeName(msg, domain))
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// dnsReply extracts the reply carried in a DNS response. It returns nil, nil
// for a packet that carries none, and a contactError for an error answer,
// which (before the first real answer) means the queries are not reaching
// the transfermapexec server.
func dnsReply(pkt []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil || !h.Response {
		return nil, nil
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		return nil, &contactError{fmt.Errorf("DNS answered %s: the queries are not reaching the transfermapexec server (check -dns-domain, or the resolver's forwarding)",
			strings.TrimPrefix(h.RCode.String(), "RCode"))}
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, nil
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			return nil, nil
		}
		if ah.Type != dnsmessage.TypeTXT {
			_ = p.SkipAnswer()
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, nil
		}
		if msg, err := base64.StdEncoding.DecodeString(strings.Join(txt.TXT, "")); err == nil {
			return msg, nil
		}
	}
}

func (a *attempt) dnsChunk() (int, error) {
	chunk := dnsChunkSize(a.opts.dnsDomain)
	if chunk < 16 {
		return 0, fmt.Errorf("-dns-domain %q is too long to leave room for data", a.opts.dnsDomain)
	}
	return chunk, nil
}

// ---- dns (UDP) ------------------------------------------------------------

type dnsTransport struct {
	c      net.Conn
	domain string
}

func (t *dnsTransport) close() error { return t.c.Close() }

func (t *dnsTransport) send(msg []byte) error {
	pkt, err := dnsQuery(msg, t.domain, uint16(randUint32()))
	if err != nil {
		return err
	}
	_, err = t.c.Write(pkt)
	return err
}

func (t *dnsTransport) recv() ([]byte, error) {
	buf := make([]byte, 4096)
	for {
		n, err := t.c.Read(buf)
		if err != nil {
			return nil, err
		}
		if msg, err := dnsReply(buf[:n]); msg != nil || err != nil {
			return msg, err
		}
	}
}

func sendDNS(a *attempt) (string, error) {
	chunk, err := a.dnsChunk()
	if err != nil {
		return "", err
	}
	var c net.Conn
	if a.opts.dnsServer != "" {
		server := a.opts.dnsServer
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		c, err = net.Dial("udp", server)
	} else {
		c, err = a.dial("udp")
	}
	if err != nil {
		return "", err
	}
	// A moderate window: real resolvers rate-limit, and through one the RTT
	// is longer, which the adaptive resend timeout picks up.
	return a.sendDatagrams(&dnsTransport{c, a.opts.dnsDomain}, dgParams{chunk: chunk, window: 32, rto: dnsTimeout})
}

func serveDNS(s *Server, addr string, _ methodSet) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	d := newDgServer(s, "dns")
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if resp := d.dnsAnswer(buf[:n], from.String(), s.dnsDomain); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	}()
	return closerFunc(func() error { d.close(); return pc.Close() }), nil
}

// dnsAnswer answers one query like an authoritative server for the domain:
// TXT queries carrying protocol messages get the reply as a TXT record;
// other names under the domain get an empty answer (not NXDOMAIN, so
// resolvers doing QNAME minimisation keep going); names outside it are
// refused.
func (d *dgServer) dnsAnswer(pkt []byte, remote, domain string) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               h.ID,
			Response:         true,
			OpCode:           h.OpCode,
			Authoritative:    true,
			RecursionDesired: h.RecursionDesired,
		},
		Questions: []dnsmessage.Question{q},
	}
	pack := func() []byte {
		b, err := resp.Pack()
		if err != nil {
			return nil
		}
		return b
	}

	suffix := "." + domain + "."
	name := strings.ToLower(q.Name.String())
	if !strings.HasSuffix(name, suffix) {
		if name != suffix[1:] {
			resp.Header.Authoritative = false
			resp.Header.RCode = dnsmessage.RCodeRefused
		}
		return pack()
	}
	if q.Type != dnsmessage.TypeTXT {
		return pack()
	}
	encoded := strings.ReplaceAll(strings.TrimSuffix(name, suffix), ".", "")
	msg, err := dnsB32.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return pack()
	}
	reply := d.handle(msg, remote)
	if reply == nil {
		return pack()
	}
	txt := base64.StdEncoding.EncodeToString(reply)
	var parts []string
	for len(txt) > 255 {
		parts = append(parts, txt[:255])
		txt = txt[255:]
	}
	parts = append(parts, txt)
	resp.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 0},
		Body:   &dnsmessage.TXTResource{TXT: parts},
	}}
	return pack()
}

// ---- dns-tcp and dot ------------------------------------------------------
//
// DNS over a stream: each message is preceded by its 2-byte length (RFC 1035
// 4.2.2). Queries are pipelined, as RFC 7766 allows.

type dnsStreamTransport struct {
	c      net.Conn
	domain string
}

func (t *dnsStreamTransport) close() error { return t.c.Close() }

func (t *dnsStreamTransport) send(msg []byte) error {
	pkt, err := dnsQuery(msg, t.domain, uint16(randUint32()))
	if err != nil {
		return err
	}
	_, err = t.c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(pkt))), pkt...))
	return err
}

func (t *dnsStreamTransport) recv() ([]byte, error) {
	for {
		var l [2]byte
		if _, err := io.ReadFull(t.c, l[:]); err != nil {
			return nil, normalizeClosed(err)
		}
		pkt := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(t.c, pkt); err != nil {
			return nil, normalizeClosed(err)
		}
		if msg, err := dnsReply(pkt); msg != nil || err != nil {
			return msg, err
		}
	}
}

// normalizeClosed reports a stream the server ended as closed, so the
// datagram layer stops reading it.
func normalizeClosed(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("server closed the connection: %w", net.ErrClosed)
	}
	return err
}

func sendDNSTCP(a *attempt) (string, error) {
	chunk, err := a.dnsChunk()
	if err != nil {
		return "", err
	}
	c, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	return a.sendDatagrams(&dnsStreamTransport{c, a.opts.dnsDomain}, dgParams{chunk: chunk, window: 32, rto: dnsTimeout})
}

func sendDoT(a *attempt) (string, error) {
	chunk, err := a.dnsChunk()
	if err != nil {
		return "", err
	}
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	c := tls.Client(raw, a.tlsConfig(alpnDoT))
	if err := a.handshake(raw, func() error { return c.HandshakeContext(a.ctx) }); err != nil {
		raw.Close()
		return "", fmt.Errorf("TLS handshake: %w", err)
	}
	detail, err := a.sendDatagrams(&dnsStreamTransport{c, a.opts.dnsDomain}, dgParams{chunk: chunk, window: 32, rto: dnsTimeout})
	return tlsDetail(c.ConnectionState()) + ", " + detail, err
}

func serveDNSTCP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return s.serveDNSStream("dns-tcp", addr, nil)
}

func serveDoT(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return s.serveDNSStream("dot", addr, s.tlsConfig(alpnDoT))
}

func (s *Server) serveDNSStream(method, addr string, tlsConf *tls.Config) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	d := newDgServer(s, method)
	go acceptLoop(ln, func(raw net.Conn) {
		defer raw.Close()
		remote := raw.RemoteAddr().String()
		c := net.Conn(&idleConn{raw, serverIdleTimeout})
		if tlsConf != nil {
			tc := tls.Server(raw, tlsConf)
			_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				s.debugf(method, "handshake with %s failed: %v", remote, err)
				return
			}
			_ = raw.SetDeadline(time.Time{})
			c = &idleConn{tc, serverIdleTimeout}
		}
		s.debugf(method, "connection from %s", remote)
		for {
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return
			}
			pkt := make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c, pkt); err != nil {
				return
			}
			resp := d.dnsAnswer(pkt, remote, s.dnsDomain)
			if resp == nil {
				continue
			}
			if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...)); err != nil {
				return
			}
		}
	})
	return closerFunc(func() error { d.close(); return ln.Close() }), nil
}

// ---- doh ------------------------------------------------------------------
//
// Each query is POSTed to /dns-query as application/dns-message over HTTP/2,
// several at once on one connection, as browsers do.

func sendDoH(a *attempt) (string, error) {
	chunk, err := a.dnsChunk()
	if err != nil {
		return "", err
	}
	tr := a.httpTransport(a.tlsConfig("h2", "http/1.1"))
	tr.ForceAttemptHTTP2 = true
	tr.DisableKeepAlives = false
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	u := "https://" + a.hostport + dohPath
	proto := ""

	t := newRTTransport(a.traced(a.ctx), func(ctx context.Context, msg []byte) ([]byte, error) {
		q, err := dnsQuery(msg, a.opts.dnsDomain, 0) // RFC 8484: ID 0, for caches
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(q))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", dohType)
		req.Header.Set("Accept", dohType)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65535))
		if err := a.checkMarker(resp, body); err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH server answered %s", resp.Status)
		}
		proto = resp.Proto
		msgOut, err := dnsReply(body)
		if msgOut == nil && err == nil {
			err = errors.New("DoH answer carried no reply")
		}
		return msgOut, err
	})
	detail, err := a.sendDatagrams(t, dgParams{chunk: chunk, window: 32, rto: time.Second})
	if proto != "" {
		detail = proto + ", " + detail
	}
	return detail, err
}

// serveDoH answers DNS-over-HTTPS: POST with a dns-message body, or GET
// with ?dns=<base64url>.
func (h *webHandler) serveDoH(w http.ResponseWriter, r *http.Request) {
	var q []byte
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != dohType {
			http.Error(w, "want "+dohType, http.StatusUnsupportedMediaType)
			return
		}
		var err error
		if q, err = io.ReadAll(io.LimitReader(r.Body, 65535)); err != nil {
			return
		}
	case http.MethodGet:
		var err error
		if q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns")); err != nil {
			http.Error(w, "bad dns parameter", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	resp := h.dg["doh"].dnsAnswer(q, r.RemoteAddr, h.s.dnsDomain)
	if resp == nil {
		http.Error(w, "not a DNS query", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", dohType)
	w.Header().Set("Cache-Control", "max-age=0")
	_, _ = w.Write(resp)
}
