package main

// Methods that carry the frame directly on a stream, with no application
// protocol around it: tcp, tls and quic. The client writes the frame; the
// server answers with a one-line verdict ("OK" or "ERR <reason>").

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ---- tcp ------------------------------------------------------------------

func sendTCP(a *attempt) (string, error) {
	c, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	return "", a.streamExchange(c)
}

func serveTCP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, func(c net.Conn) { s.serveStream("tcp", c) })
	return ln, nil
}

// ---- tls ------------------------------------------------------------------

func sendTLS(a *attempt) (string, error) {
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	c := tls.Client(raw, a.tlsConfig(alpnRaw))
	if err := a.handshake(raw, func() error { return c.HandshakeContext(a.ctx) }); err != nil {
		raw.Close()
		return "", fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsDetail(c.ConnectionState()), a.streamExchange(c)
}

func serveTLS(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	cfg := s.tlsConfig(alpnRaw)
	go acceptLoop(ln, func(raw net.Conn) {
		c := tls.Server(raw, cfg)
		_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
		if err := c.Handshake(); err != nil {
			s.debugf("tls", "handshake with %s failed: %v", raw.RemoteAddr(), err)
			raw.Close()
			return
		}
		_ = raw.SetDeadline(time.Time{})
		s.serveStream("tls", c)
	})
	return ln, nil
}

// streamExchange sends the frame on c, then reads the server's verdict.
func (a *attempt) streamExchange(c net.Conn) error {
	defer c.Close()
	stop := context.AfterFunc(a.ctx, func() { c.Close() })
	defer stop()

	if _, err := io.Copy(c, a.source()); err != nil {
		// The server may have refused the transfer part-way and closed the
		// connection; its verdict explains that better than the write error.
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var refused *refusedError
		if verr := readVerdict(c); errors.As(verr, &refused) {
			return verr
		}
		return fmt.Errorf("sending failed: %w", err)
	}
	return readVerdict(a.guard.reader(c))
}

func (s *Server) serveStream(method string, c net.Conn) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	s.debugf(method, "connection from %s", remote)
	ic := &idleConn{c, serverIdleTimeout}
	writeVerdict(ic, s.receive(method, remote, ic))
}

// ---- quic -----------------------------------------------------------------

func (a *attempt) quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: a.opts.connectTimeout,
		MaxIdleTimeout:       a.opts.idleTimeout,
		KeepAlivePeriod:      a.opts.idleTimeout / 3,
	}
}

func sendQUIC(a *attempt) (string, error) {
	dialCtx, cancel := context.WithTimeout(a.ctx, a.opts.connectTimeout)
	conn, err := quic.DialAddr(dialCtx, a.addr, a.tlsConfig(alpnRaw), a.quicConfig())
	cancel()
	if err != nil {
		return "", a.unreachable(err)
	}
	a.connected.Store(true)
	a.logf("connected to %s", conn.RemoteAddr())
	defer conn.CloseWithError(0, "done")
	stop := context.AfterFunc(a.ctx, func() { conn.CloseWithError(1, "client gave up") })
	defer stop()

	stream, err := conn.OpenStreamSync(a.ctx)
	if err != nil {
		return "", fmt.Errorf("opening stream: %w", err)
	}
	if _, err := io.Copy(stream, a.source()); err != nil {
		return "", fmt.Errorf("sending failed: %w", err)
	}
	// Close our side (FIN); the server's verdict follows on the same stream.
	if err := stream.Close(); err != nil {
		return "", fmt.Errorf("closing stream: %w", err)
	}
	return "QUIC " + conn.ConnectionState().Version.String(), readVerdict(a.guard.reader(stream))
}

func serveQUIC(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := quic.ListenAddr(addr, s.tlsConfig(alpnRaw), &quic.Config{
		MaxIdleTimeout:  serverIdleTimeout,
		KeepAlivePeriod: serverIdleTimeout / 3,
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return // listener closed
			}
			go s.serveQUICConn(conn)
		}
	}()
	return ln, nil
}

func (s *Server) serveQUICConn(conn *quic.Conn) {
	remote := conn.RemoteAddr().String()
	s.debugf("quic", "connection from %s", remote)
	defer conn.CloseWithError(0, "bye")

	ctx, cancel := context.WithTimeout(context.Background(), serverIdleTimeout)
	stream, err := conn.AcceptStream(ctx)
	cancel()
	if err != nil {
		s.debugf("quic", "no stream from %s: %v", remote, err)
		return
	}
	is := &idleStream{stream, serverIdleTimeout}
	writeVerdict(is, s.receive("quic", remote, is))
	_ = stream.Close()

	// Give the client a moment to read the verdict and close the connection.
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

// idleStream is a QUIC stream whose every read and write must complete
// within d. (QUIC's own idle timeout does not fire while keep-alives flow.)
type idleStream struct {
	*quic.Stream
	d time.Duration
}

func (s *idleStream) Read(p []byte) (int, error) {
	_ = s.Stream.SetReadDeadline(time.Now().Add(s.d))
	return s.Stream.Read(p)
}

func (s *idleStream) Write(p []byte) (int, error) {
	_ = s.Stream.SetWriteDeadline(time.Now().Add(s.d))
	return s.Stream.Write(p)
}
