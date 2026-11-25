package main

// The xmpp method is a chat client's session (RFC 6120): open a stream,
// STARTTLS, SASL (ANONYMOUS), bind a resource, then send the frame with
// In-Band Bytestreams (XEP-0047), XMPP's standard way to move a file inside
// the stream: <open/>, a series of <data/> blocks (base64, 4 KB each, each
// acknowledged), and <close/>. The answer to <close/> is the verdict: a
// result, or an error whose text gives the reason.

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	nsStream = "http://etherx.jabber.org/streams"
	nsTLS    = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL   = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind   = "urn:ietf:params:xml:ns:xmpp-bind"
	nsIBB    = "http://jabber.org/protocol/ibb"
	nsErrors = "urn:ietf:params:xml:ns:xmpp-stanzas"

	xmppBlock  = 4096
	xmppWindow = 16
)

type xmppFeatures struct {
	StartTLS   *struct{} `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`
	Mechanisms []string  `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms>mechanism"`
	Bind       *struct{} `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
}

type xmppIQ struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
	Bind *struct {
		Resource string `xml:"resource"`
	} `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Open *struct {
		SID       string `xml:"sid,attr"`
		BlockSize int    `xml:"block-size,attr"`
	} `xml:"http://jabber.org/protocol/ibb open"`
	Data *struct {
		SID  string `xml:"sid,attr"`
		Seq  int    `xml:"seq,attr"`
		Text string `xml:",chardata"`
	} `xml:"http://jabber.org/protocol/ibb data"`
	Close *struct {
		SID string `xml:"sid,attr"`
	} `xml:"http://jabber.org/protocol/ibb close"`
	Error *struct {
		Text string `xml:"urn:ietf:params:xml:ns:xmpp-stanzas text"`
	} `xml:"error"`
}

// xmppStream reads stanzas from one XML stream. The decoder reads through a
// bufio.Reader it never reads ahead of, so after STARTTLS or SASL the stream
// can restart on the same connection.
type xmppStream struct {
	c   net.Conn
	br  *bufio.Reader
	dec *xml.Decoder
}

func newXMPPStream(c net.Conn) *xmppStream {
	x := &xmppStream{c: c}
	x.restart()
	return x
}

func (x *xmppStream) restart() {
	x.br = bufio.NewReader(x.c)
	x.dec = xml.NewDecoder(x.br)
}

// readHeader reads the peer's <stream:stream> opening tag.
func (x *xmppStream) readHeader() (xml.StartElement, error) {
	for {
		tok, err := x.dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local != "stream" {
				return se, fmt.Errorf("expected a stream header, got <%s>", se.Name.Local)
			}
			return se, nil
		}
	}
}

// next returns the next top-level element, or io.EOF at </stream:stream>.
func (x *xmppStream) next() (xml.StartElement, error) {
	for {
		tok, err := x.dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			if t.Name.Local == "stream" {
				return xml.StartElement{}, io.EOF
			}
		}
	}
}

func (x *xmppStream) write(format string, args ...any) error {
	_, err := fmt.Fprintf(x.c, format, args...)
	return err
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func sendXMPP(a *attempt) (string, error) {
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer raw.Close()
	stop := closeOnDone(a, raw)
	defer stop()

	domain := a.host
	if net.ParseIP(domain) != nil {
		domain = "transfermapexec.test"
	}
	x := newXMPPStream(raw)
	open := func() (xmppFeatures, error) {
		var f xmppFeatures
		if err := x.write("<?xml version='1.0'?><stream:stream to='%s' version='1.0' xml:lang='en' xmlns='jabber:client' xmlns:stream='%s'>", xmlEscape(domain), nsStream); err != nil {
			return f, err
		}
		if _, err := x.readHeader(); err != nil {
			return f, err
		}
		se, err := x.next()
		if err != nil {
			return f, err
		}
		if se.Name.Local != "features" {
			return f, fmt.Errorf("expected stream features, got <%s>", se.Name.Local)
		}
		return f, x.dec.DecodeElement(&f, &se)
	}
	expect := func(name string) error {
		se, err := x.next()
		if err != nil {
			return err
		}
		var v struct {
			Text string `xml:"text"`
		}
		_ = x.dec.DecodeElement(&v, &se)
		if se.Name.Local != name {
			return &refusedError{fmt.Sprintf("<%s> %s", se.Name.Local, strings.TrimSpace(v.Text))}
		}
		return nil
	}

	// Stream, STARTTLS, SASL and resource binding, within -connect-timeout.
	var tlsState tls.ConnectionState
	err = a.handshake(raw, func() error {
		f, err := open()
		if err != nil {
			return err
		}
		if f.StartTLS == nil {
			return errors.New("server does not offer STARTTLS")
		}
		if err := x.write("<starttls xmlns='%s'/>", nsTLS); err != nil {
			return err
		}
		if err := expect("proceed"); err != nil {
			return err
		}
		tc := tls.Client(raw, a.tlsConfig())
		if err := tc.HandshakeContext(a.ctx); err != nil {
			return fmt.Errorf("TLS handshake: %w", err)
		}
		tlsState = tc.ConnectionState()
		x.c = tc
		x.restart()

		if f, err = open(); err != nil {
			return err
		}
		mech := ""
		for _, m := range f.Mechanisms {
			if m == "ANONYMOUS" || (m == "PLAIN" && mech == "") {
				mech = m
			}
		}
		switch mech {
		case "ANONYMOUS":
			err = x.write("<auth xmlns='%s' mechanism='ANONYMOUS'/>", nsSASL)
		case "PLAIN":
			cred := base64.StdEncoding.EncodeToString([]byte("\x00" + appName + "\x00" + appName))
			err = x.write("<auth xmlns='%s' mechanism='PLAIN'>%s</auth>", nsSASL, cred)
		default:
			return fmt.Errorf("no usable SASL mechanism (server offers %v)", f.Mechanisms)
		}
		if err != nil {
			return err
		}
		if err := expect("success"); err != nil {
			return err
		}
		x.restart()
		if _, err = open(); err != nil {
			return err
		}
		if err := x.write("<iq type='set' id='bind'><bind xmlns='%s'><resource>%s</resource></bind></iq>", nsBind, appName); err != nil {
			return err
		}
		return expect("iq")
	})
	if err != nil {
		return "", fmt.Errorf("XMPP session setup: %w", err)
	}
	a.guard.touch()

	sid := fmt.Sprintf("mt%08x", randUint32())
	to := "upload@" + domain + "/" + appName
	if err := x.write("<iq type='set' id='open' to='%s'><open xmlns='%s' block-size='%d' sid='%s' stanza='iq'/></iq>", xmlEscape(to), nsIBB, xmppBlock, sid); err != nil {
		return "", err
	}

	// The reader collects the answers to our iqs.
	type answer struct {
		id  string
		err error
	}
	answers := make(chan answer, xmppWindow+2)
	go func() {
		for {
			se, err := x.next()
			if err != nil {
				answers <- answer{err: err}
				return
			}
			var iq xmppIQ
			if err := x.dec.DecodeElement(&iq, &se); err != nil || se.Name.Local != "iq" {
				continue
			}
			switch iq.Type {
			case "result":
				answers <- answer{id: iq.ID}
			case "error":
				text := "error"
				if iq.Error != nil && iq.Error.Text != "" {
					text = iq.Error.Text
				}
				answers <- answer{id: iq.ID, err: &refusedError{text}}
			}
		}
	}()
	wait := func() (answer, error) {
		select {
		case an := <-answers:
			if an.err != nil {
				return an, an.err
			}
			a.guard.touch()
			return an, nil
		case <-a.ctx.Done():
			return answer{}, a.ctx.Err()
		}
	}
	if _, err := wait(); err != nil {
		return "", fmt.Errorf("IBB open: %w", err)
	}

	src := a.source()
	buf := make([]byte, xmppBlock)
	inflight, seq := 0, 0
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			for inflight >= xmppWindow {
				if _, err := wait(); err != nil {
					return "", err
				}
				inflight--
			}
			if err := x.write("<iq type='set' id='d%d' to='%s'><data xmlns='%s' seq='%d' sid='%s'>%s</data></iq>",
				seq, xmlEscape(to), nsIBB, seq&0xffff, sid, base64.StdEncoding.EncodeToString(buf[:n])); err != nil {
				return "", fmt.Errorf("sending failed: %w", err)
			}
			inflight++
			seq++
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
	}
	for ; inflight > 0; inflight-- {
		if _, err := wait(); err != nil {
			return "", err
		}
	}
	if err := x.write("<iq type='set' id='close' to='%s'><close xmlns='%s' sid='%s'/></iq>", xmlEscape(to), nsIBB, sid); err != nil {
		return "", err
	}
	if _, err := wait(); err != nil {
		return "", err
	}
	_ = x.write("</stream:stream>")
	return fmt.Sprintf("STARTTLS %s, IBB %d blocks", tls.VersionName(tlsState.Version), seq), nil
}

func serveXMPP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.serveXMPPConn)
	return ln, nil
}

func (s *Server) serveXMPPConn(raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr().String()
	x := newXMPPStream(&idleConn{raw, serverIdleTimeout})
	domain := "transfermapexec.test"

	header := func(features string) error {
		se, err := x.readHeader()
		if err != nil {
			return err
		}
		for _, at := range se.Attr {
			if at.Name.Local == "to" && at.Value != "" {
				domain = at.Value
			}
		}
		return x.write("<?xml version='1.0'?><stream:stream from='%s' id='%08x' version='1.0' xml:lang='en' xmlns='jabber:client' xmlns:stream='%s'><stream:features>%s</stream:features>",
			xmlEscape(domain), randUint32(), nsStream, features)
	}
	expect := func(name string) bool {
		se, err := x.next()
		if err != nil {
			return false
		}
		_ = x.dec.Skip()
		return se.Name.Local == name
	}

	// STARTTLS is required, as on any real server.
	if header(fmt.Sprintf("<starttls xmlns='%s'><required/></starttls>", nsTLS)) != nil || !expect("starttls") {
		s.debugf("xmpp", "no STARTTLS from %s", remote)
		return
	}
	_ = x.write("<proceed xmlns='%s'/>", nsTLS)
	tc := tls.Server(raw, s.tlsConfig())
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		s.debugf("xmpp", "TLS handshake with %s failed: %v", remote, err)
		return
	}
	_ = raw.SetDeadline(time.Time{})
	x.c = &idleConn{tc, serverIdleTimeout}
	x.restart()

	if header(fmt.Sprintf("<mechanisms xmlns='%s'><mechanism>ANONYMOUS</mechanism><mechanism>PLAIN</mechanism></mechanisms>", nsSASL)) != nil || !expect("auth") {
		return
	}
	_ = x.write("<success xmlns='%s'/>", nsSASL)
	x.restart()
	if header(fmt.Sprintf("<bind xmlns='%s'/>", nsBind)) != nil {
		return
	}
	s.debugf("xmpp", "session from %s", remote)

	var (
		pw   *io.PipeWriter
		done chan error
		sid  string
	)
	defer func() {
		if pw != nil {
			pw.CloseWithError(errors.New("client disconnected"))
		}
	}()
	result := func(id string) { _ = x.write("<iq type='result' id='%s'/>", xmlEscape(id)) }
	fail := func(id string, err error) {
		_ = x.write("<iq type='error' id='%s'><error type='cancel'><not-acceptable xmlns='%s'/><text xmlns='%s'>%s</text></error></iq>",
			xmlEscape(id), nsErrors, nsErrors, xmlEscape(oneLine(err.Error())))
	}
	for {
		se, err := x.next()
		if err != nil {
			_ = x.write("</stream:stream>")
			return
		}
		if se.Name.Local != "iq" {
			_ = x.dec.Skip()
			continue
		}
		var iq xmppIQ
		if err := x.dec.DecodeElement(&iq, &se); err != nil {
			return
		}
		switch {
		case iq.Bind != nil:
			res := iq.Bind.Resource
			if res == "" {
				res = "default"
			}
			_ = x.write("<iq type='result' id='%s'><bind xmlns='%s'><jid>anon-%08x@%s/%s</jid></bind></iq>",
				xmlEscape(iq.ID), nsBind, randUint32(), xmlEscape(domain), xmlEscape(res))
		case iq.Open != nil:
			if pw != nil {
				fail(iq.ID, errors.New("a bytestream is already open"))
				continue
			}
			sid = iq.Open.SID
			var pr *io.PipeReader
			pr, pw = io.Pipe()
			done = make(chan error, 1)
			go func() {
				err := s.receive("xmpp", remote, pr)
				if err == nil {
					_, _ = io.Copy(io.Discard, pr)
					pr.Close()
				} else {
					pr.CloseWithError(err)
				}
				done <- err
			}()
			result(iq.ID)
		case iq.Data != nil:
			if pw == nil || iq.Data.SID != sid {
				fail(iq.ID, errors.New("no such bytestream"))
				continue
			}
			data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(iq.Data.Text), ""))
			if err == nil {
				_, err = pw.Write(data)
			}
			if err != nil {
				fail(iq.ID, err)
				continue
			}
			result(iq.ID)
		case iq.Close != nil:
			if pw == nil || iq.Close.SID != sid {
				fail(iq.ID, errors.New("no such bytestream"))
				continue
			}
			pw.Close()
			err := <-done
			pw = nil
			if err != nil {
				fail(iq.ID, err)
			} else {
				result(iq.ID)
			}
		default:
			if iq.Type == "get" || iq.Type == "set" {
				result(iq.ID) // e.g. a legacy session request
			}
		}
	}
}
