package main

// HTTP without a body: http-query, http-cookie and http-header send the
// frame as many small GET requests, each carrying one message of the
// datagram protocol (dgram.go) base64url-encoded in
//
//	http-query   the URL:     GET /search?q=<data>&hl=en
//	http-cookie  a cookie:    Cookie: theme=light; session=<data>
//	http-header  a header:    Authorization: Bearer <data>
//
// Inspection that only looks at request bodies sees nothing. Each response
// body is the server's reply, base64-encoded. Requests run several at a time
// over keep-alive connections, as a browser's would.

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	queryPath  = "/search"
	cookieName = "session"
	headerPath = "/api/v1/status"
)

func sendHTTPQuery(a *attempt) (string, error) {
	// ~1900-character URLs: within what every browser, proxy and server takes.
	return a.sendHTTPGet(1400, func(base, data string) (*http.Request, error) {
		return http.NewRequest(http.MethodGet, base+queryPath+"?q="+data+"&hl=en", nil)
	})
}

func sendHTTPCookie(a *attempt) (string, error) {
	// ~4 KB cookies: the size browsers allow per cookie.
	return a.sendHTTPGet(3000, func(base, data string) (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, base+"/", nil)
		if err == nil {
			req.Header.Set("Cookie", "theme=light; "+cookieName+"="+data)
		}
		return req, err
	})
}

func sendHTTPHeader(a *attempt) (string, error) {
	return a.sendHTTPGet(3000, func(base, data string) (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, base+headerPath, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+data)
		}
		return req, err
	})
}

// sendHTTPGet runs the datagram protocol over GET requests that build puts
// each base64url-encoded message into.
func (a *attempt) sendHTTPGet(chunk int, build func(base, data string) (*http.Request, error)) (string, error) {
	tr := a.httpTransport(nil)
	tr.DisableKeepAlives = false
	tr.MaxConnsPerHost = 8
	tr.MaxIdleConnsPerHost = 8
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	base := "http://" + a.hostport

	t := newRTTransport(a.traced(a.ctx), func(ctx context.Context, msg []byte) ([]byte, error) {
		req, err := build(base, base64.RawURLEncoding.EncodeToString(msg))
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		req.Header.Set("User-Agent", appName)
		req.Header.Set("Accept", "*/*")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err := a.checkMarker(resp, body); err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNoContent {
			return nil, nil // the server dropped it (too far ahead); it will be sent again
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server answered %s", resp.Status)
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	})
	return a.sendDatagrams(t, dgParams{chunk: chunk, window: 8, rto: time.Second})
}

// serveGetMethods handles the http-* GETs; it returns false for a request
// that is not one of them.
func (h *webHandler) serveGetMethods(w http.ResponseWriter, r *http.Request) bool {
	var method, data string
	if h.on["http-query"] && r.URL.Path == queryPath {
		method, data = "http-query", r.URL.Query().Get("q")
	}
	if data == "" && h.on["http-cookie"] {
		if c, err := r.Cookie(cookieName); err == nil {
			method, data = "http-cookie", c.Value
		}
	}
	if data == "" && h.on["http-header"] {
		if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			method, data = "http-header", tok
		}
	}
	if data == "" {
		return false
	}
	msg, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		http.Error(w, "bad data", http.StatusBadRequest)
		return true
	}
	reply := h.dg[method].handle(msg, r.RemoteAddr)
	if reply == nil {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(reply))
	return true
}
