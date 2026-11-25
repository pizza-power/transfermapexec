package main

// ssh and sftp share one SSH server, as on port 22.
//
// ssh opens a session, runs a remote command and pipes the frame into its
// stdin, like `ssh host cmd < file`. The command's exit status is the
// verdict, with the reason for a failure on its stderr.
//
// sftp uploads the frame as a file with SFTP (pkg/sftp), like
// `sftp host <<< "put file"`. The server checks and stores it when the client
// closes the file; the status of that close is the verdict.
//
// The server generates a fresh ed25519 host key in memory at startup and
// accepts any client without authentication; the client does not check the
// host key. It is a test endpoint: it runs no commands and serves no files.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sshUser    = appName
	sshCommand = "transfermapexec-receive"
)

// sshConnect opens an SSH connection to the method's port.
func (a *attempt) sshConnect() (*ssh.Client, string, func(), error) {
	raw, err := a.dialTCP()
	if err != nil {
		return nil, "", nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshUser)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // intentional: the server's key is generated per run
		Timeout:         a.opts.connectTimeout,
	}
	var (
		sc    ssh.Conn
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
	)
	err = a.handshake(raw, func() (err error) {
		sc, chans, reqs, err = ssh.NewClientConn(raw, a.addr, cfg)
		return err
	})
	if err != nil {
		raw.Close()
		return nil, "", nil, fmt.Errorf("SSH handshake: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	stop := context.AfterFunc(a.ctx, func() { client.Close() })
	return client, string(sc.ServerVersion()), func() { stop(); client.Close() }, nil
}

func sendSSH(a *attempt) (string, error) {
	client, detail, done, err := a.sshConnect()
	if err != nil {
		return "", err
	}
	defer done()

	sess, err := client.NewSession()
	if err != nil {
		return detail, fmt.Errorf("opening session: %w", err)
	}
	defer sess.Close()
	var stderr bytes.Buffer
	sess.Stdin = a.source()
	sess.Stderr = &stderr
	if err := sess.Run(sshCommand); err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			return detail, &refusedError{strings.TrimSpace(stderr.String())}
		}
		return detail, err
	}
	return detail, nil
}

func sendSFTP(a *attempt) (string, error) {
	client, detail, done, err := a.sshConnect()
	if err != nil {
		return "", err
	}
	defer done()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return detail, fmt.Errorf("starting SFTP: %w", err)
	}
	defer sc.Close()
	f, err := sc.Create(a.uploadName())
	if err != nil {
		var se *sftp.StatusError
		if errors.As(err, &se) {
			return detail, &refusedError{"creating the file: " + strings.TrimSpace(se.Error())}
		}
		return detail, fmt.Errorf("creating file: %w", err)
	}
	if _, err := io.Copy(f, a.source()); err != nil {
		f.Close()
		return detail, fmt.Errorf("sending failed: %w", err)
	}
	// Closing the file is when the server checks and stores it.
	if err := f.Close(); err != nil {
		var se *sftp.StatusError
		if errors.As(err, &se) {
			return detail, &refusedError{strings.TrimSpace(se.Error())}
		}
		return detail, err
	}
	return detail + ", SFTP v3", nil
}

func serveSSH(s *Server, addr string, on methodSet) (io.Closer, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln, func(c net.Conn) { s.serveSSHConn(c, cfg, on) })
	return ln, nil
}

func (s *Server) serveSSHConn(c net.Conn, cfg *ssh.ServerConfig, on methodSet) {
	remote := c.RemoteAddr().String()
	sc, chans, reqs, err := ssh.NewServerConn(&idleConn{c, serverIdleTimeout}, cfg)
	if err != nil {
		s.debugf("ssh", "handshake with %s failed: %v", remote, err)
		c.Close()
		return
	}
	defer sc.Close()
	s.debugf("ssh", "connection from %s (%s)", remote, sc.ClientVersion())
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.serveSSHSession(remote, ch, chReqs, on)
	}
}

// serveSSHSession takes a session's first exec request (ssh: whatever the
// command, the transfer arrives on stdin) or sftp subsystem request.
func (s *Server) serveSSHSession(remote string, ch ssh.Channel, reqs <-chan *ssh.Request, on methodSet) {
	started := false
	for req := range reqs {
		var run func()
		switch {
		case started:
		case req.Type == "exec" && on["ssh"]:
			run = func() { s.sshExec(remote, ch) }
		case req.Type == "subsystem" && on["sftp"] && bytes.HasSuffix(req.Payload, []byte("sftp")):
			run = func() { s.sftpSession(remote, ch) }
		}
		if req.WantReply {
			_ = req.Reply(run != nil, nil)
		}
		if run != nil {
			started = true
			go run()
		}
	}
}

func (s *Server) sshExec(remote string, ch ssh.Channel) {
	defer ch.Close()
	status := uint32(0)
	if err := s.receive("ssh", remote, ch); err != nil {
		status = 1
		fmt.Fprintln(ch.Stderr(), oneLine(err.Error()))
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
}

func (s *Server) sftpSession(remote string, ch ssh.Channel) {
	defer ch.Close()
	h := &sftpHandlers{s: s, remote: remote}
	srv := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
	_ = srv.Serve()
	srv.Close()
}

// sftpHandlers accept uploads (each checked and stored by the server's
// receive when the client closes it) and refuse everything else.
type sftpHandlers struct {
	s      *Server
	remote string
}

func (h *sftpHandlers) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	dir := h.s.out
	tmp, err := os.CreateTemp(dir, ".transfermapexec-sftp-*.part")
	if err != nil {
		h.s.logf("sftp", "cannot create a temporary file: %v", err)
		return nil, errors.New("server cannot create a file")
	}
	return &sftpUpload{h: h, path: r.Filepath, tmp: tmp}, nil
}

func (h *sftpHandlers) Fileread(*sftp.Request) (io.ReaderAt, error) {
	return nil, sftp.ErrSSHFxPermissionDenied
}

func (h *sftpHandlers) Filecmd(r *sftp.Request) error {
	if r.Method == "Setstat" {
		return nil
	}
	return sftp.ErrSSHFxPermissionDenied
}

func (h *sftpHandlers) Filelist(*sftp.Request) (sftp.ListerAt, error) {
	return nil, os.ErrNotExist
}

// sftpUpload collects the writes (which may arrive out of order) in a
// temporary file, and hands the whole file to receive on close.
type sftpUpload struct {
	h    *sftpHandlers
	path string
	tmp  *os.File

	mu   sync.Mutex
	size int64
}

func (u *sftpUpload) WriteAt(p []byte, off int64) (int, error) {
	n, err := u.tmp.WriteAt(p, off)
	u.mu.Lock()
	u.size = max(u.size, off+int64(n))
	u.mu.Unlock()
	return n, err
}

func (u *sftpUpload) Close() error {
	defer func() {
		u.tmp.Close()
		os.Remove(u.tmp.Name())
	}()
	u.h.s.debugf("sftp", "upload %q from %s closed (%d bytes)", u.path, u.h.remote, u.size)
	return u.h.s.receive("sftp", u.h.remote, io.NewSectionReader(u.tmp, 0, u.size))
}
