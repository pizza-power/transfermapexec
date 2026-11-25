package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// Every method carries the same frame, whatever it wraps it in (an HTTP body,
// an email attachment, DNS query names, ping payloads, ...):
//
//	[4  bytes] magic           "MTX1"
//	[1  byte ] type            0x01 = file, 0x02 = text
//	[2  bytes] name length     big-endian uint16
//	[N  bytes] name            filename (file) or optional label (text), UTF-8
//	[8  bytes] payload length  big-endian uint64
//	[32 bytes] SHA-256         of the payload
//	[M  bytes] payload         raw file bytes or UTF-8 text
//
// The server reads exactly payload-length bytes and checks them against the
// SHA-256 before it stores anything or confirms delivery.
const (
	frameMagic = "MTX1"

	typeFile byte = 0x01
	typeText byte = 0x02

	maxNameLen = 0xffff // bounded by the uint16 name-length field
)

type header struct {
	kind       byte
	name       string
	payloadLen uint64
	sum        [sha256.Size]byte
}

func (h header) marshal() ([]byte, error) {
	if len(h.name) > maxNameLen {
		return nil, fmt.Errorf("name too long: %d bytes (max %d)", len(h.name), maxNameLen)
	}
	buf := make([]byte, 0, 4+1+2+len(h.name)+8+sha256.Size)
	buf = append(buf, frameMagic...)
	buf = append(buf, h.kind)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.name)))
	buf = append(buf, h.name...)
	buf = binary.BigEndian.AppendUint64(buf, h.payloadLen)
	buf = append(buf, h.sum[:]...)
	return buf, nil
}

// readHeader reads and validates a frame header from r.
func readHeader(r io.Reader) (header, error) {
	var h header

	var fixed [4 + 1 + 2]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return h, err
	}
	if string(fixed[:4]) != frameMagic {
		return h, errors.New("not a transfermapexec frame (bad magic)")
	}
	h.kind = fixed[4]
	if h.kind != typeFile && h.kind != typeText {
		return h, fmt.Errorf("unknown payload type 0x%02x", h.kind)
	}
	if nameLen := binary.BigEndian.Uint16(fixed[5:]); nameLen > 0 {
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(r, name); err != nil {
			return h, err
		}
		h.name = string(name)
	}

	var tail [8 + sha256.Size]byte
	if _, err := io.ReadFull(r, tail[:]); err != nil {
		return h, err
	}
	h.payloadLen = binary.BigEndian.Uint64(tail[:8])
	// Lengths are handled as int64 from here on (io.LimitReader, io.Copy).
	if h.payloadLen > math.MaxInt64 {
		return h, fmt.Errorf("payload length %d is out of range", h.payloadLen)
	}
	copy(h.sum[:], tail[8:])
	return h, nil
}

// frame is the client's view of one transfer: the encoded header followed by
// the payload. It can be read any number of times and at any offset, so every
// method (including the chunked, out-of-order datagram ones) can send it
// without the payload being held in memory.
type frame struct {
	h       header
	head    []byte
	payload io.ReaderAt
	size    int64 // len(head) + payload length
}

// newFileFrame builds a frame for the file at path, stored on the server as
// name. The caller closes the returned file when done.
func newFileFrame(path, name string) (*frame, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("cannot stat file: %w", err)
	}
	if fi.IsDir() {
		f.Close()
		return nil, nil, fmt.Errorf("%q is a directory, not a file", path)
	}
	fr, err := newFrame(typeFile, name, f, fi.Size())
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return fr, f, nil
}

func newTextFrame(text, label string) (*frame, error) {
	return newFrame(typeText, label, bytes.NewReader([]byte(text)), int64(len(text)))
}

func newFrame(kind byte, name string, payload io.ReaderAt, n int64) (*frame, error) {
	sum := sha256.New()
	if _, err := io.Copy(sum, io.NewSectionReader(payload, 0, n)); err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	h := header{kind: kind, name: name, payloadLen: uint64(n)}
	copy(h.sum[:], sum.Sum(nil))
	head, err := h.marshal()
	if err != nil {
		return nil, err
	}
	return &frame{h: h, head: head, payload: payload, size: int64(len(head)) + n}, nil
}

// open returns a fresh reader over the whole frame.
func (f *frame) open() *io.SectionReader { return io.NewSectionReader(f, 0, f.size) }

// ReadAt implements io.ReaderAt across the header and the payload.
func (f *frame) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= f.size {
		return 0, io.EOF
	}
	want := len(p)
	if rem := f.size - off; int64(len(p)) > rem {
		p = p[:rem]
	}
	n := 0
	if hl := int64(len(f.head)); off < hl {
		n = copy(p, f.head[off:])
	}
	if n < len(p) {
		m, err := f.payload.ReadAt(p[n:], off+int64(n)-int64(len(f.head)))
		n += m
		if n < len(p) {
			if err == nil || err == io.EOF {
				err = errors.New("the file got shorter while it was being sent")
			}
			return n, err
		}
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

// kindName is "file" or "text", for messages.
func (h header) kindName() string {
	if h.kind == typeFile {
		return "file"
	}
	return "text"
}
