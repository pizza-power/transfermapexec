package main

// The grpc method makes a client-streaming gRPC call over HTTP/2 and TLS:
//
//	service transfermapexec.v1.Transfer {
//	  rpc Upload(stream Chunk) returns (Result);
//	}
//	message Chunk { bytes data = 1; }
//	message Result {}
//
// It is real gRPC on the wire (POST /transfermapexec.v1.Transfer/Upload,
// content-type application/grpc, te: trailers, length-prefixed protobuf
// messages, grpc-status in the trailers), implemented on Go's HTTP/2 stack
// rather than grpc-go. The grpc-status trailer is the verdict.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	grpcPath     = "/transfermapexec.v1.Transfer/Upload"
	grpcChunk    = 64 << 10
	grpcMaxMsg   = 4 << 20 // gRPC's default receive limit
	grpcOK       = "0"
	grpcInvalid  = "3"  // INVALID_ARGUMENT
	grpcUnimpl   = "12" // UNIMPLEMENTED
	grpcInternal = "13" // INTERNAL
)

// protoBytes encodes a protobuf message with data as bytes field 1.
func protoBytes(data []byte) []byte {
	b := binary.AppendUvarint(nil, 1<<3|2) // field 1, length-delimited
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}

// protoField1 returns the bytes of field 1 in a protobuf message (all
// occurrences, concatenated), skipping any other fields.
func protoField1(msg []byte) ([]byte, error) {
	var out []byte
	for len(msg) > 0 {
		tag, n := binary.Uvarint(msg)
		if n <= 0 {
			return nil, errors.New("bad protobuf tag")
		}
		msg = msg[n:]
		switch tag & 7 {
		case 0: // varint
			if _, n = binary.Uvarint(msg); n <= 0 {
				return nil, errors.New("bad protobuf varint")
			}
			msg = msg[n:]
		case 1: // 64-bit
			if len(msg) < 8 {
				return nil, errors.New("short protobuf field")
			}
			msg = msg[8:]
		case 5: // 32-bit
			if len(msg) < 4 {
				return nil, errors.New("short protobuf field")
			}
			msg = msg[4:]
		case 2: // length-delimited
			l, n := binary.Uvarint(msg)
			if n <= 0 || uint64(len(msg)-n) < l {
				return nil, errors.New("bad protobuf length")
			}
			if tag>>3 == 1 {
				out = append(out, msg[n:n+int(l)]...)
			}
			msg = msg[n+int(l):]
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", tag&7)
		}
	}
	return out, nil
}

func sendGRPC(a *attempt) (string, error) {
	tr := a.httpTransport(a.tlsConfig("h2")) // gRPC needs HTTP/2
	tr.ForceAttemptHTTP2 = true
	defer tr.CloseIdleConnections()

	// The request body is the stream of Chunk messages, each prefixed with
	// its compressed flag (0) and length.
	pr, pw := io.Pipe()
	go func() {
		src := a.source()
		buf := make([]byte, grpcChunk)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				msg := protoBytes(buf[:n])
				prefix := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(msg)))
				if _, werr := pw.Write(append(prefix, msg...)); werr != nil {
					return
				}
			}
			if err == io.EOF {
				pw.Close()
				return
			}
			if err != nil {
				pw.CloseWithError(err)
				return
			}
		}
	}()

	req, err := http.NewRequestWithContext(a.traced(a.ctx), http.MethodPost, "https://"+a.hostport+grpcPath, pr)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("User-Agent", appName+"-grpc")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		pr.CloseWithError(err)
		return "", a.httpError(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(a.guard.reader(resp.Body), 65536))
	if err := a.checkMarker(resp, body); err != nil {
		return resp.Proto, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.Proto, fmt.Errorf("server answered %s", resp.Status)
	}
	// The status is in the trailers, or in the headers of a trailers-only
	// response.
	status, msg := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if status == "" {
		status, msg = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if m, err := url.PathUnescape(msg); err == nil {
		msg = m
	}
	switch status {
	case grpcOK:
		return resp.Proto + ", grpc-status 0", nil
	case "":
		return resp.Proto, errors.New("no grpc-status in the response")
	}
	return resp.Proto, &refusedError{fmt.Sprintf("grpc-status %s: %s", status, msg)}
}

// handleGRPC serves the Upload call.
func (s *Server) handleGRPC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	finish := func(status string, err error) {
		w.WriteHeader(http.StatusOK)
		if status == grpcOK {
			_, _ = w.Write([]byte{0, 0, 0, 0, 0}) // an empty Result message
		}
		w.Header().Set("Grpc-Status", status)
		if err != nil {
			w.Header().Set("Grpc-Message", url.PathEscape(oneLine(err.Error())))
		}
	}
	if r.ProtoMajor != 2 {
		http.Error(w, "gRPC needs HTTP/2", http.StatusHTTPVersionNotSupported)
		return
	}
	if r.URL.Path != grpcPath {
		finish(grpcUnimpl, fmt.Errorf("unknown method %s", r.URL.Path))
		return
	}
	s.debugf("grpc", "call %s from %s", r.URL.Path, r.RemoteAddr)

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := s.receive("grpc", r.RemoteAddr, pr)
		if err == nil {
			_, _ = io.Copy(io.Discard, pr)
			pr.Close()
		} else {
			pr.CloseWithError(err)
		}
		done <- err
	}()

	in := bufio.NewReader(&idleBody{r: r.Body, rc: http.NewResponseController(w), d: serverIdleTimeout})
	var readErr error
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(in, hdr[:]); err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if hdr[0] != 0 {
			readErr = errors.New("compressed messages are not supported")
			break
		}
		if n > grpcMaxMsg {
			readErr = fmt.Errorf("message of %d bytes is over the %d-byte limit", n, grpcMaxMsg)
			break
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(in, msg); err != nil {
			readErr = err
			break
		}
		data, err := protoField1(msg)
		if err != nil {
			readErr = err
			break
		}
		if _, err := pw.Write(data); err != nil {
			break // the receiver stopped; its error says why
		}
	}
	if readErr != nil {
		pw.CloseWithError(readErr)
	} else {
		pw.Close()
	}
	if err := <-done; err != nil {
		status := grpcInvalid
		if strings.Contains(err.Error(), "server ") {
			status = grpcInternal
		}
		finish(status, err)
		return
	}
	finish(grpcOK, nil)
}
