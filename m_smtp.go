package main

// The smtp method sends an email whose body is the frame, base64-encoded as an
// application/octet-stream attachment. The server's reply to the end of the
// message (250 or 554) is the verdict.
//
// The server is a minimal SMTP receiver: EHLO/HELO, MAIL, RCPT, DATA, RSET,
// NOOP, QUIT. It accepts any sender and recipient and relays nothing.

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

const (
	smtpFrom = "transfermapexec@localhost"
	smtpTo   = "inbox@transfermapexec.test"
)

func sendSMTP(a *attempt) (string, error) {
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer raw.Close()
	stopClose := closeOnDone(a, raw)
	defer stopClose()

	var c *smtp.Client
	if err := a.handshake(raw, func() (err error) {
		c, err = smtp.NewClient(raw, a.host) // reads the 220 greeting
		return err
	}); err != nil {
		return "", fmt.Errorf("SMTP greeting: %w", smtpErr(err))
	}
	defer c.Close()

	if err := c.Mail(smtpFrom); err != nil {
		return "", fmt.Errorf("MAIL FROM: %w", smtpErr(err))
	}
	if err := c.Rcpt(smtpTo); err != nil {
		return "", fmt.Errorf("RCPT TO: %w", smtpErr(err))
	}
	w, err := c.Data()
	if err != nil {
		return "", fmt.Errorf("DATA: %w", smtpErr(err))
	}

	name := a.uploadName()
	// The DATA writer turns "\n" into CRLF and dot-stuffs lines for us.
	fmt.Fprintf(w, "From: %s <%s>\n", appName, smtpFrom)
	fmt.Fprintf(w, "To: <%s>\n", smtpTo)
	fmt.Fprintf(w, "Subject: %s\n", mime.QEncoding.Encode("utf-8", appName+": "+name))
	fmt.Fprintf(w, "Date: %s\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(w, "Message-ID: <%d.%08x@%s>\n", time.Now().UnixNano(), randUint32(), appName)
	fmt.Fprintf(w, "MIME-Version: 1.0\n")
	fmt.Fprintf(w, "Content-Type: %s\n", mime.FormatMediaType("application/octet-stream", map[string]string{"name": name}))
	fmt.Fprintf(w, "Content-Disposition: %s\n", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	fmt.Fprintf(w, "Content-Transfer-Encoding: base64\n\n")

	enc := base64.NewEncoder(base64.StdEncoding, &lineWrapper{w: w, width: 76})
	if _, err := io.Copy(enc, a.source()); err != nil {
		return "", fmt.Errorf("sending failed: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("sending failed: %w", err)
	}
	_, _ = io.WriteString(w, "\n")
	// Closing the DATA writer sends the final "." and reads the server's
	// reply to the whole message: the verdict.
	if err := w.Close(); err != nil {
		var te *textproto.Error
		if errors.As(err, &te) {
			return "", &refusedError{fmt.Sprintf("%d %s", te.Code, te.Msg)}
		}
		return "", err
	}
	_ = c.Quit()
	return "", nil
}

// smtpErr makes a server's SMTP error reply read like one.
func smtpErr(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		return fmt.Errorf("server replied %d %s", te.Code, te.Msg)
	}
	return err
}

// lineWrapper breaks the base64 stream into lines of width characters.
type lineWrapper struct {
	w     io.Writer
	width int
	col   int
}

func (lw *lineWrapper) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), lw.width-lw.col)
		if _, err := lw.w.Write(p[:n]); err != nil {
			return written, err
		}
		written += n
		lw.col += n
		p = p[n:]
		if lw.col == lw.width {
			if _, err := io.WriteString(lw.w, "\n"); err != nil {
				return written, err
			}
			lw.col = 0
		}
	}
	return written, nil
}

func serveSMTP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.serveSMTPConn)
	return ln, nil
}

func (s *Server) serveSMTPConn(c net.Conn) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	s.debugf("smtp", "connection from %s", remote)
	tp := textproto.NewConn(&idleConn{c, serverIdleTimeout})
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }

	reply("220 %s ESMTP ready", appName)
	var haveMail, haveRcpt bool
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, _, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			reply("250-%s hello", appName)
			reply("250 HELP")
		case "HELO":
			reply("250 %s hello", appName)
		case "MAIL":
			haveMail, haveRcpt = true, false
			reply("250 OK")
		case "RCPT":
			if !haveMail {
				reply("503 MAIL first")
				continue
			}
			haveRcpt = true
			reply("250 OK")
		case "DATA":
			if !haveMail || !haveRcpt {
				reply("503 MAIL and RCPT first")
				continue
			}
			reply("354 End data with <CR><LF>.<CR><LF>")
			dr := tp.DotReader()
			err := s.receiveMail(remote, dr)
			_, _ = io.Copy(io.Discard, dr) // read up to the final "."
			if err != nil {
				reply("554 Transaction failed: %s", oneLine(err.Error()))
			} else {
				reply("250 OK: stored")
			}
			haveMail, haveRcpt = false, false
		case "RSET":
			haveMail, haveRcpt = false, false
			reply("250 OK")
		case "NOOP":
			reply("250 OK")
		case "VRFY":
			reply("252 Cannot verify, but will accept")
		case "QUIT":
			reply("221 Bye")
			return
		default:
			reply("502 Command not implemented")
		}
	}
}

// receiveMail decodes the message's base64 body and receives the frame in it.
func (s *Server) receiveMail(remote string, r io.Reader) error {
	msg, err := mail.ReadMessage(bufio.NewReader(r))
	if err != nil {
		s.logf("smtp", "bad message from %s: %v", remote, err)
		return fmt.Errorf("cannot parse message: %v", err)
	}
	if cte := msg.Header.Get("Content-Transfer-Encoding"); !strings.EqualFold(strings.TrimSpace(cte), "base64") {
		s.logf("smtp", "message from %s is not base64-encoded (%q)", remote, cte)
		return errors.New("expected a base64-encoded body")
	}
	// The base64 decoder skips the line breaks between encoded lines.
	return s.receive("smtp", remote, base64.NewDecoder(base64.StdEncoding, msg.Body))
}
