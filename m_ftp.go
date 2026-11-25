package main

// The ftp method logs in anonymously and uploads the frame with STOR over a
// passive-mode data connection (EPSV, falling back to PASV). The server's
// reply after the upload (226, or 451 with a reason) is the verdict.
//
// The server is a minimal FTP receiver: it accepts any login, takes uploads
// in passive mode only, stores nothing under the uploaded name itself (the
// frame carries the real name), and serves no downloads or listings.

import (
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func sendFTP(a *attempt) (string, error) {
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer raw.Close()
	stopClose := closeOnDone(a, raw)
	defer stopClose()

	tp := textproto.NewConn(raw)
	if err := a.handshake(raw, func() error {
		_, _, err := tp.ReadResponse(220)
		return err
	}); err != nil {
		return "", fmt.Errorf("FTP greeting: %w", err)
	}

	// cmd sends one command and reads its reply. expect is a reply code, or
	// a single digit for any reply in that class (2 = 2xx).
	cmd := func(expect int, format string, args ...any) (int, string, error) {
		id, err := tp.Cmd(format, args...)
		if err != nil {
			return 0, "", err
		}
		tp.StartResponse(id)
		defer tp.EndResponse(id)
		return tp.ReadResponse(expect)
	}

	code, _, err := cmd(0, "USER anonymous")
	if err != nil {
		return "", fmt.Errorf("USER: %w", err)
	}
	if code == 331 {
		if _, _, err := cmd(230, "PASS %s", smtpFrom); err != nil {
			return "", fmt.Errorf("login: %w", err)
		}
	} else if code != 230 {
		return "", fmt.Errorf("USER: unexpected reply %d", code)
	}
	if _, _, err := cmd(200, "TYPE I"); err != nil {
		return "", fmt.Errorf("TYPE I: %w", err)
	}

	// Passive mode: ask for a data port, then connect to it. The address in
	// a PASV reply is ignored in favour of -host, which is what works through
	// NAT.
	mode := "EPSV"
	_, msg, err := cmd(229, "EPSV")
	var dataPort int
	if err == nil {
		dataPort, err = parseEPSV(msg)
	}
	if err != nil {
		mode = "PASV"
		_, msg, err = cmd(227, "PASV")
		if err != nil {
			return "", fmt.Errorf("passive mode: %w", err)
		}
		if dataPort, err = parsePASV(msg); err != nil {
			return "", err
		}
	}
	d := net.Dialer{Timeout: a.opts.connectTimeout}
	data, err := d.DialContext(a.ctx, "tcp", net.JoinHostPort(a.ip, strconv.Itoa(dataPort)))
	if err != nil {
		return mode, fmt.Errorf("FTP data connection to port %d failed (firewalls often allow the control port but not data ports): %w", dataPort, err)
	}
	defer data.Close()
	stopData := closeOnDone(a, data)
	defer stopData()

	if _, _, err := cmd(1, "STOR %s", a.uploadName()); err != nil {
		return mode, fmt.Errorf("STOR: %w", err)
	}
	if _, err := io.Copy(data, a.source()); err != nil {
		return mode, fmt.Errorf("sending failed: %w", err)
	}
	data.Close() // end of file

	// The reply to STOR's upload is the verdict.
	if _, msg, err := tp.ReadResponse(2); err != nil {
		if te, ok := err.(*textproto.Error); ok {
			return mode, &refusedError{fmt.Sprintf("%d %s", te.Code, te.Msg)}
		}
		return mode, fmt.Errorf("no delivery confirmation from server: %w", err)
	} else {
		a.logf("server: %s", msg)
	}
	_, _, _ = cmd(0, "QUIT")
	return "passive (" + mode + ")", nil
}

// parseEPSV extracts the port from "Entering Extended Passive Mode (|||port|)".
func parseEPSV(msg string) (int, error) {
	start := strings.Index(msg, "(")
	end := strings.LastIndex(msg, ")")
	if start < 0 || end <= start {
		return 0, fmt.Errorf("cannot parse EPSV reply %q", msg)
	}
	fields := strings.Split(msg[start+1:end], "|")
	if len(fields) != 5 {
		return 0, fmt.Errorf("cannot parse EPSV reply %q", msg)
	}
	port, err := strconv.Atoi(fields[3])
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("bad port in EPSV reply %q", msg)
	}
	return port, nil
}

// parsePASV extracts the port from "Entering Passive Mode (h1,h2,h3,h4,p1,p2)".
func parsePASV(msg string) (int, error) {
	start := strings.Index(msg, "(")
	end := strings.LastIndex(msg, ")")
	if start < 0 || end <= start {
		return 0, fmt.Errorf("cannot parse PASV reply %q", msg)
	}
	f := strings.Split(msg[start+1:end], ",")
	if len(f) != 6 {
		return 0, fmt.Errorf("cannot parse PASV reply %q", msg)
	}
	p1, err1 := strconv.Atoi(strings.TrimSpace(f[4]))
	p2, err2 := strconv.Atoi(strings.TrimSpace(f[5]))
	if err1 != nil || err2 != nil || p1 < 0 || p1 > 255 || p2 < 0 || p2 > 255 {
		return 0, fmt.Errorf("bad port in PASV reply %q", msg)
	}
	return p1<<8 | p2, nil
}

func serveFTP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, s.serveFTPConn)
	return ln, nil
}

func (s *Server) serveFTPConn(c net.Conn) {
	defer c.Close()
	remote := c.RemoteAddr().String()
	s.debugf("ftp", "connection from %s", remote)
	tp := textproto.NewConn(&idleConn{c, serverIdleTimeout})
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }

	var pasv net.Listener
	closePasv := func() {
		if pasv != nil {
			pasv.Close()
			pasv = nil
		}
	}
	defer closePasv()

	reply("220 %s FTP ready", appName)
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch verb = strings.ToUpper(verb); verb {
		case "USER":
			reply("331 Any password will do")
		case "PASS":
			reply("230 Logged in")
		case "SYST":
			reply("215 UNIX Type: L8")
		case "FEAT":
			reply("211-Features:")
			reply(" EPSV")
			reply(" PASV")
			reply(" UTF8")
			reply("211 End")
		case "OPTS", "TYPE", "MODE", "STRU":
			reply("200 OK")
		case "PWD":
			reply(`257 "/" is the current directory`)
		case "CWD":
			reply("250 OK")
		case "NOOP":
			reply("200 OK")
		case "EPSV", "PASV":
			closePasv()
			local := c.LocalAddr().(*net.TCPAddr)
			ln, err := net.Listen("tcp", net.JoinHostPort(local.IP.String(), strconv.Itoa(s.ftpPasvPort)))
			if err != nil {
				reply("425 Cannot open a data port: %s", oneLine(err.Error()))
				continue
			}
			port := ln.Addr().(*net.TCPAddr).Port
			if verb == "EPSV" {
				pasv = ln
				reply("229 Entering Extended Passive Mode (|||%d|)", port)
				continue
			}
			ip4 := local.IP.To4()
			if ip4 == nil {
				ln.Close()
				reply("425 PASV needs IPv4; use EPSV")
				continue
			}
			pasv = ln
			reply("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip4[0], ip4[1], ip4[2], ip4[3], port>>8, port&0xff)
		case "STOR":
			if pasv == nil {
				reply("425 Use EPSV or PASV first")
				continue
			}
			reply("150 Ok to send data")
			_ = pasv.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
			dc, err := pasv.Accept()
			closePasv()
			if err != nil {
				reply("425 No data connection: %s", oneLine(err.Error()))
				continue
			}
			// Only the client on the control connection may send the data.
			if !dc.RemoteAddr().(*net.TCPAddr).IP.Equal(c.RemoteAddr().(*net.TCPAddr).IP) {
				dc.Close()
				reply("425 Data connection from the wrong address")
				continue
			}
			s.debugf("ftp", "STOR %q from %s", arg, remote)
			err = s.receive("ftp", remote, &idleConn{dc, serverIdleTimeout})
			dc.Close()
			if err != nil {
				reply("451 %s", oneLine(err.Error()))
			} else {
				reply("226 Transfer complete")
			}
		case "QUIT":
			reply("221 Bye")
			return
		default:
			reply("502 Command not implemented")
		}
	}
}
