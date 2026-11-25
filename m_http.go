package main

// The web methods. One handler serves every method that rides on HTTP, so
// methods given the same port share one server, as they would on 443:
//
//	cleartext listener ("http"):  http, http-query, http-cookie, http-header
//	TLS listener ("https"):       https, doh, grpc, ws, webrtc (signaling)
//	QUIC listener ("http3"):      http3
//
// http, https and http3 POST the frame as the request body to /upload; the
// status code is the verdict. The others are in their own files.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	uploadPath = "/upload"
	wsPath     = "/ws"

	// wsSubprotocol is carried in the Sec-WebSocket-Protocol header; the
	// server turns away WebSocket clients that do not offer it.
	wsSubprotocol = "transfermapexec"

	// httpMarkerHeader is set on every response from the web methods'
	// server, so the client can tell it from anything else that answers.
	httpMarkerHeader = "X-Transfermapexec"
)

// ---- client side ----------------------------------------------------------

// httpTransport returns a transport that dials the target within
// -connect-timeout. Like any Go HTTP client it honours HTTP_PROXY,
// HTTPS_PROXY and NO_PROXY, so the web methods can be tested through a proxy.
func (a *attempt) httpTransport(tlsConf *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         a.dialContext,
		TLSClientConfig:     tlsConf,
		TLSHandshakeTimeout: a.opts.connectTimeout,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
}

// traced marks the attempt connected when the HTTP client gets a connection.
func (a *attempt) traced(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !a.connected.Swap(true) {
				a.logf("connected to %s", info.Conn.RemoteAddr())
			}
		},
	})
}

// httpError explains a failed request: before contact, as unreachable.
func (a *attempt) httpError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err // drop the repeated `Post "https://..."` prefix
	}
	if !a.connected.Load() {
		return a.unreachable(err)
	}
	return err
}

// checkMarker returns an error if resp did not come from a transfermapexec
// server: another program on the port, or a proxy or filter on the path
// that intercepted the request (a block page, say).
func (a *attempt) checkMarker(resp *http.Response, body []byte) error {
	if resp.Header.Get(httpMarkerHeader) != "" {
		return nil
	}
	who := ""
	if sv := resp.Header.Get("Server"); sv != "" {
		who = fmt.Sprintf(", Server: %q", oneLine(sv))
	}
	text := oneLine(strings.TrimSpace(string(body)))
	if len(text) > 80 {
		text = text[:77] + "..."
	}
	return &contactError{fmt.Errorf("something other than a transfermapexec server answered on %s (%s%s): another program on that port, or a proxy/filter on the path? body: %q",
		endpoint(a.m, a.port), resp.Status, who, text)}
}

func sendHTTP(a *attempt) (string, error) {
	tr := a.httpTransport(nil)
	defer tr.CloseIdleConnections()
	return a.httpUpload(&http.Client{Transport: tr}, "http://"+a.hostport+uploadPath)
}

func sendHTTPS(a *attempt) (string, error) {
	tr := a.httpTransport(a.tlsConfig("h2", "http/1.1"))
	tr.ForceAttemptHTTP2 = true // a custom TLS config otherwise turns HTTP/2 off
	defer tr.CloseIdleConnections()
	return a.httpUpload(&http.Client{Transport: tr}, "https://"+a.hostport+uploadPath)
}

func sendHTTP3(a *attempt) (string, error) {
	tr := &http3.Transport{
		TLSClientConfig: a.tlsConfig(http3.NextProtoH3),
		QUICConfig:      a.quicConfig(),
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, a.opts.connectTimeout)
			defer cancel()
			conn, err := quic.DialAddr(dialCtx, a.addr, tlsConf, conf)
			if err == nil {
				a.connected.Store(true)
				a.logf("connected to %s", conn.RemoteAddr())
			}
			return conn, err
		},
	}
	defer tr.Close()
	return a.httpUpload(&http.Client{Transport: tr}, "https://"+a.hostport+uploadPath)
}

// httpUpload POSTs the frame to u and reads the server's verdict from the
// status code. The detail it returns is the protocol used, e.g. "HTTP/2.0".
func (a *attempt) httpUpload(client *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(a.traced(a.ctx), http.MethodPost, u, a.source())
	if err != nil {
		return "", err
	}
	req.ContentLength = a.frame.size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", appName)

	resp, err := client.Do(req)
	if err != nil {
		return "", a.httpError(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(a.guard.reader(resp.Body), 4096))
	if err := a.checkMarker(resp, body); err != nil {
		return resp.Proto, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Proto, &refusedError{fmt.Sprintf("%s: %s", resp.Status, oneLine(strings.TrimSpace(string(body))))}
	}
	return resp.Proto, nil
}

func sendWS(a *attempt) (string, error) {
	// The opening handshake is an HTTP/1.1 Upgrade, so only http/1.1 is offered.
	tr := a.httpTransport(a.tlsConfig("http/1.1"))
	defer tr.CloseIdleConnections()

	dialCtx, cancel := context.WithTimeout(a.traced(a.ctx), a.opts.connectTimeout)
	conn, resp, err := websocket.Dial(dialCtx, "wss://"+a.hostport+wsPath, &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: tr},
		Subprotocols: []string{wsSubprotocol},
	})
	cancel() // the timeout covers the dial and handshake only, not the transfer
	if err != nil {
		if resp != nil {
			if merr := a.checkMarker(resp, nil); merr != nil {
				return "", merr
			}
		}
		if !a.connected.Load() {
			return "", a.unreachable(err)
		}
		return "", fmt.Errorf("WebSocket handshake: %w", err)
	}
	defer conn.CloseNow()

	// The server sends nothing but a close frame. Reading for it from the
	// start keeps pings answered during a long upload, and lets a refusal that
	// arrives part-way through be reported for what it is.
	closed := make(chan error, 1)
	go func() {
		_, _, err := conn.Read(a.ctx)
		if err == nil {
			err = errors.New("server sent data, expected only a close frame")
		}
		closed <- err
	}()
	failed := func(err error) error {
		select {
		case cerr := <-closed:
			var ce websocket.CloseError
			if errors.As(cerr, &ce) {
				return &refusedError{wsCloseText(ce)}
			}
		case <-time.After(time.Second):
		}
		return err
	}

	// One binary message carries the whole frame, streamed frame by frame.
	w, err := conn.Writer(a.ctx, websocket.MessageBinary)
	if err != nil {
		return "", failed(fmt.Errorf("opening message: %w", err))
	}
	if _, err := io.Copy(w, a.source()); err != nil {
		return "", failed(fmt.Errorf("sending failed: %w", err))
	}
	if err := w.Close(); err != nil {
		return "", failed(fmt.Errorf("ending message: %w", err))
	}
	a.guard.touch()

	// A normal closure from the server is the delivery confirmation.
	var ce websocket.CloseError
	if err := <-closed; !errors.As(err, &ce) {
		return "", fmt.Errorf("no delivery confirmation from server: %w", err)
	}
	if ce.Code != websocket.StatusNormalClosure {
		return "", &refusedError{wsCloseText(ce)}
	}
	return "", nil
}

func wsCloseText(ce websocket.CloseError) string {
	if ce.Reason == "" {
		return fmt.Sprintf("close code %d", ce.Code)
	}
	return fmt.Sprintf("%s (close code %d)", ce.Reason, ce.Code)
}

// ---- server side ----------------------------------------------------------

func (s *Server) httpServer(name string, h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       serverIdleTimeout,
		// net/http reports failed TLS handshakes and malformed requests here:
		// per-connection detail, so it is only shown with -v.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	if s.verbose {
		srv.ErrorLog = log.New(s.logger.Writer(), "["+name+"] ", log.LstdFlags)
	}
	return srv
}

// webHandler routes every request on one HTTP listener to the method it
// belongs to, among the methods the listener serves.
type webHandler struct {
	s      *Server
	on     methodSet
	secure bool
	dg     map[string]*dgServer // the methods that use the datagram protocol
	rtc    *rtcServer
}

// newWebHandler builds the handler for the methods in on. Methods that
// cannot start (webrtc without its UDP port) are left out and reported.
func (s *Server) newWebHandler(on methodSet, secure bool) (*webHandler, partialStart) {
	h := &webHandler{s: s, on: on, secure: secure, dg: map[string]*dgServer{}}
	for _, name := range []string{"doh", "http-query", "http-cookie", "http-header"} {
		if on[name] {
			h.dg[name] = newDgServer(s, name)
		}
	}
	partial := partialStart{}
	if on["webrtc"] {
		rtc, err := s.newRTCServer()
		if err != nil {
			partial["webrtc"] = err
		} else {
			h.rtc = rtc
		}
	}
	return h, partial
}

func (h *webHandler) close() {
	for _, d := range h.dg {
		d.close()
	}
	if h.rtc != nil {
		h.rtc.close()
	}
}

func (h *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(httpMarkerHeader, "1")
	switch {
	case h.on["ws"] && isWebSocketUpgrade(r):
		h.s.handleWS(w, r)
		return
	case h.on["grpc"] && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"):
		h.s.handleGRPC(w, r)
		return
	case h.on["doh"] && r.URL.Path == dohPath:
		h.serveDoH(w, r)
		return
	case h.rtc != nil && r.URL.Path == webrtcPath:
		h.rtc.handleOffer(w, r)
		return
	}
	if r.Method == http.MethodGet && h.serveGetMethods(w, r) {
		return
	}
	upload := "http"
	if h.secure {
		upload = "https"
	}
	if h.on[upload] && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		h.s.handleUpload(upload, w, r)
		return
	}
	http.NotFound(w, r)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleUpload receives a frame POSTed (or PUT) as the request body.
func (s *Server) handleUpload(method string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set(httpMarkerHeader, "1")
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		w.Header().Set("Allow", "POST, PUT")
		http.Error(w, "send the data with POST", http.StatusMethodNotAllowed)
		return
	}
	s.debugf(method, "%s %s from %s (%s)", r.Method, r.URL.Path, r.RemoteAddr, r.Proto)
	body := &idleBody{r: r.Body, rc: http.NewResponseController(w), d: serverIdleTimeout}
	if err := s.receive(method, r.RemoteAddr, body); err != nil {
		http.Error(w, oneLine(err.Error()), http.StatusUnprocessableEntity)
		return
	}
	_, _ = io.WriteString(w, "OK\n")
}

// idleBody is a request body whose every read must complete within d.
type idleBody struct {
	r           io.Reader
	rc          *http.ResponseController
	d           time.Duration
	unsupported bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if !b.unsupported {
		// HTTP/3 has no per-request deadlines; QUIC's idle timeout covers it.
		if err := b.rc.SetReadDeadline(time.Now().Add(b.d)); errors.Is(err, http.ErrNotSupported) {
			b.unsupported = true
		}
	}
	return b.r.Read(p)
}

// serveHTTP is the cleartext web listener.
func serveHTTP(s *Server, addr string, on methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h, partial := s.newWebHandler(on, false)
	srv := s.httpServer("http", h)
	go srv.Serve(ln)
	return closerFunc(func() error { h.close(); return srv.Close() }), partial.err()
}

// serveHTTPS is the TLS web listener: HTTP/2 and HTTP/1.1.
func serveHTTPS(s *Server, addr string, on methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	h, partial := s.newWebHandler(on, true)
	srv := s.httpServer("https", h)
	srv.TLSConfig = s.tlsConfig("h2", "http/1.1")
	go srv.ServeTLS(ln, "", "")
	return closerFunc(func() error { h.close(); return srv.Close() }), partial.err()
}

func serveHTTP3(s *Server, addr string, _ methodSet) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http3.Server{
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleUpload("http3", w, r) }),
		TLSConfig:  http3.ConfigureTLSConfig(s.tlsConfig()),
		QUICConfig: &quic.Config{MaxIdleTimeout: serverIdleTimeout},
	}
	go srv.Serve(pc)
	return closerFunc(func() error {
		srv.Close()
		return pc.Close()
	}), nil
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	remote := r.RemoteAddr
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{wsSubprotocol}})
	if err != nil {
		s.debugf("ws", "handshake with %s failed: %v", remote, err)
		return
	}
	defer conn.CloseNow()
	s.debugf("ws", "connection from %s", remote)
	if conn.Subprotocol() != wsSubprotocol {
		_ = conn.Close(websocket.StatusPolicyViolation, "subprotocol "+wsSubprotocol+" required")
		return
	}
	// The frame is streamed rather than buffered whole, so the library's
	// default 32 KiB per-message limit is lifted.
	conn.SetReadLimit(-1)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	guard := newIdleGuard(serverIdleTimeout, serverIdleTimeout, cancel)
	defer guard.stop()

	typ, msg, err := conn.Reader(ctx)
	if err != nil {
		s.debugf("ws", "no message from %s: %v", remote, err)
		return
	}
	if typ != websocket.MessageBinary {
		_ = conn.Close(websocket.StatusUnsupportedData, "binary message required")
		return
	}
	if err := s.receive("ws", remote, guard.reader(msg)); err != nil {
		reason := oneLine(err.Error())
		if len(reason) > 120 { // close reasons are limited to 123 bytes
			reason = reason[:120]
		}
		_ = conn.Close(websocket.StatusPolicyViolation, reason)
		return
	}
	// A normal closure confirms delivery.
	_ = conn.Close(websocket.StatusNormalClosure, "")
}
