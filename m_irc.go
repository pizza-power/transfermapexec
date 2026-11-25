package main

// The irc method registers with the server like any IRC client (NICK,
// USER), joins #transfermapexec and posts the frame there, base64-encoded, as
// a stream of PRIVMSG lines. The server checks and stores the data and
// answers with a NOTICE: "OK" or "ERR <reason>", the verdict.

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	ircChannel = "#transfermapexec"
	ircServer  = appName
	ircLineLen = 400 // characters of base64 per PRIVMSG, within IRC's 512-byte lines
)

// ircParse splits a line into prefix, command and parameters.
func ircParse(line string) (prefix, cmd string, params []string) {
	line = strings.TrimRight(line, "\r\n")
	if strings.HasPrefix(line, ":") {
		prefix, line, _ = strings.Cut(line[1:], " ")
	}
	for line != "" {
		if strings.HasPrefix(line, ":") {
			params = append(params, line[1:])
			break
		}
		var p string
		p, line, _ = strings.Cut(line, " ")
		if cmd == "" {
			cmd = strings.ToUpper(p)
		} else if p != "" {
			params = append(params, p)
		}
	}
	return prefix, cmd, params
}

// ircLines turns written base64 text into PRIVMSG lines.
type ircLines struct {
	send func(format string, args ...any) error
	buf  []byte
}

func (l *ircLines) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	for len(l.buf) >= ircLineLen {
		if err := l.send("PRIVMSG %s :%s", ircChannel, l.buf[:ircLineLen]); err != nil {
			return 0, err
		}
		l.buf = l.buf[ircLineLen:]
	}
	return len(p), nil
}

func (l *ircLines) flush() error {
	if len(l.buf) == 0 {
		return nil
	}
	err := l.send("PRIVMSG %s :%s", ircChannel, l.buf)
	l.buf = nil
	return err
}

func sendIRC(a *attempt) (string, error) {
	c, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer c.Close()
	stop := closeOnDone(a, c)
	defer stop()
	r := bufio.NewReader(c)
	var wmu sync.Mutex
	send := func(format string, args ...any) error {
		wmu.Lock()
		defer wmu.Unlock()
		_, err := fmt.Fprintf(c, format+"\r\n", args...)
		return err
	}

	nick := fmt.Sprintf("mt%06x", randUint32()&0xffffff)
	// Register and join, answering PINGs, within -connect-timeout.
	err = a.handshake(c, func() error {
		if err := send("NICK %s", nick); err != nil {
			return err
		}
		if err := send("USER %s 0 * :%s", nick, appName); err != nil {
			return err
		}
		joined := false
		for !joined {
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			_, cmd, params := ircParse(line)
			switch cmd {
			case "PING":
				_ = send("PONG :%s", strings.Join(params, " "))
			case "001":
				if err := send("JOIN %s", ircChannel); err != nil {
					return err
				}
			case "366": // end of the channel's names: joined
				joined = true
			case "ERROR", "432", "433", "465", "473", "474", "475":
				return &refusedError{strings.TrimSpace(line)}
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("IRC registration: %w", err)
	}

	verdict := make(chan string, 1)
	readErr := make(chan error, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				readErr <- err
				return
			}
			_, cmd, params := ircParse(line)
			switch {
			case cmd == "PING":
				_ = send("PONG :%s", strings.Join(params, " "))
			case cmd == "NOTICE" && len(params) == 2 && params[0] == nick:
				verdict <- params[1]
				return
			case cmd == "ERROR":
				readErr <- fmt.Errorf("server: %s", strings.TrimSpace(line))
				return
			}
		}
	}()

	lines := &ircLines{send: send}
	enc := base64.NewEncoder(base64.StdEncoding, lines)
	if _, err := io.Copy(enc, a.source()); err != nil {
		return "", fmt.Errorf("sending failed: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	if err := lines.flush(); err != nil {
		return "", err
	}

	select {
	case v := <-verdict:
		_ = send("QUIT :done")
		return "", verdictText(v)
	case err := <-readErr:
		return "", fmt.Errorf("no delivery confirmation: %w", err)
	case <-a.ctx.Done():
		return "", a.ctx.Err()
	}
}

func serveIRC(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.serveIRCConn)
	return ln, nil
}

func (s *Server) serveIRCConn(raw net.Conn) {
	defer raw.Close()
	remote := raw.RemoteAddr().String()
	c := &idleConn{raw, serverIdleTimeout}
	r := bufio.NewReaderSize(c, 4096)
	var wmu sync.Mutex
	send := func(format string, args ...any) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = fmt.Fprintf(c, format+"\r\n", args...)
	}
	host, _, _ := net.SplitHostPort(remote)

	var nick, user string
	var pw *io.PipeWriter
	defer func() {
		if pw != nil {
			pw.CloseWithError(fmt.Errorf("client disconnected"))
		}
	}()
	registered := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		_, cmd, params := ircParse(line)
		switch cmd {
		case "NICK":
			if len(params) > 0 {
				nick = params[0]
			}
		case "USER":
			if len(params) > 0 {
				user = params[0]
			}
		case "PING":
			send(":%s PONG %s :%s", ircServer, ircServer, strings.Join(params, " "))
		case "JOIN":
			if registered && len(params) > 0 {
				ch := params[0]
				send(":%s!%s@%s JOIN %s", nick, user, host, ch)
				send(":%s 353 %s = %s :%s", ircServer, nick, ch, nick)
				send(":%s 366 %s %s :End of /NAMES list.", ircServer, nick, ch)
			}
		case "PRIVMSG":
			if !registered || len(params) < 2 || !strings.EqualFold(params[0], ircChannel) {
				continue
			}
			if pw == nil {
				var pr *io.PipeReader
				pr, pw = io.Pipe()
				go func(nick string) {
					verdict := "OK"
					if err := s.receive("irc", remote, base64.NewDecoder(base64.StdEncoding, pr)); err != nil {
						verdict = "ERR " + oneLine(err.Error())
						pr.CloseWithError(err)
					} else {
						pr.Close()
					}
					send(":%s NOTICE %s :%s", ircServer, nick, verdict)
				}(nick)
			}
			_, _ = io.WriteString(pw, params[1])
		case "QUIT":
			send("ERROR :Closing link: %s (Quit)", host)
			return
		}
		if !registered && nick != "" && user != "" {
			registered = true
			s.debugf("irc", "%s registered from %s", nick, remote)
			send(":%s 001 %s :Welcome to the %s IRC network %s", ircServer, nick, appName, nick)
			send(":%s 002 %s :Your host is %s", ircServer, nick, ircServer)
			send(":%s 003 %s :This server was created for transfer tests", ircServer, nick)
			send(":%s 004 %s %s 1.0 o o", ircServer, nick, ircServer)
			send(":%s 422 %s :MOTD File is missing", ircServer, nick)
		}
	}
}
