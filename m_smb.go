package main

// The smb method writes the frame to a file on an SMB share, the way a
// Windows `copy report.pdf \\server\upload\` would: SMB2/3 negotiate, NTLMv2
// session setup, tree connect, create, writes, close. The client is
// hirochachacha/go-smb2; the server is the SMB2/3 server from
// macos-fuse-t/go-smb2, with an in-memory share.
//
// The server checks and stores the file when the client closes it. SMB's
// close response cannot carry that verdict (the server library ignores
// close errors), so the client then reads it back from "<name>.mtresult" on
// the same share: "OK", or "ERR <reason>".

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
	smbsrv "github.com/macos-fuse-t/go-smb2/server"
	"github.com/macos-fuse-t/go-smb2/vfs"
	"github.com/sirupsen/logrus"
)

const (
	smbShare        = "upload"
	smbUser         = appName
	smbPassword     = appName
	smbResultSuffix = ".mtresult"
)

func sendSMB(a *attempt) (string, error) {
	raw, err := a.dialTCP()
	if err != nil {
		return "", err
	}
	defer raw.Close()
	stop := closeOnDone(a, raw)
	defer stop()

	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: smbUser, Password: smbPassword}}
	var sess *smb2.Session
	if err := a.handshake(raw, func() (err error) {
		sess, err = d.DialContext(a.ctx, raw)
		return err
	}); err != nil {
		return "", fmt.Errorf("SMB session setup: %w", err)
	}
	defer sess.Logoff()

	share, err := sess.Mount(smbShare)
	if err != nil {
		return "", fmt.Errorf("mounting \\\\%s\\%s: %w", a.host, smbShare, err)
	}
	defer share.Umount()

	name := a.uploadName()
	f, err := share.Create(name)
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", name, err)
	}
	if _, err := io.Copy(f, a.source()); err != nil {
		f.Close()
		return "", fmt.Errorf("sending failed: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing %s: %w", name, err)
	}
	a.guard.touch()

	res, err := share.ReadFile(name + smbResultSuffix)
	if err != nil {
		return "", fmt.Errorf("no delivery confirmation (reading %s%s): %w", name, smbResultSuffix, err)
	}
	return `\\` + a.host + `\` + smbShare, verdictText(string(res))
}

// verdictText turns an "OK" / "ERR <reason>" verdict into an error.
func verdictText(v string) error {
	v = strings.TrimSpace(v)
	switch {
	case v == "OK":
		return nil
	case strings.HasPrefix(v, "ERR "):
		return &refusedError{v[4:]}
	}
	return fmt.Errorf("unexpected verdict from server: %q", v)
}

func serveSMB(s *Server, addr string, _ methodSet) (io.Closer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	if s.verbose {
		logger.SetOutput(s.logger.Writer())
		logger.SetLevel(logrus.WarnLevel)
	}
	smbsrv.SetLogger(logger)

	// The library's NTLM authenticator keeps one login's state in a field
	// shared by every connection, so concurrent logins clobber each other.
	// Each connection therefore gets a server instance of its own, all
	// sharing one share.
	fsys := newSMBFS(s)
	shares := map[string]vfs.VFSFileSystem{smbShare: fsys}
	var mu sync.Mutex
	live := map[*smbsrv.Server]bool{}
	go acceptLoop(ln, func(c net.Conn) {
		srv := smbsrv.NewServer(
			&smbsrv.ServerConfig{AllowGuest: true, MaxIOReads: 4, MaxIOWrites: 4},
			&smbsrv.NTLMAuthenticator{
				UserPassword: map[string]string{smbUser: smbPassword},
				NbDomain:     "TRANSFERMAPEXEC",
				NbName:       "TRANSFERMAPEXEC",
				DnsName:      "transfermapexec",
				DnsDomain:    "transfermapexec.test",
				AllowGuest:   true,
			},
			shares,
		)
		mu.Lock()
		live[srv] = true
		mu.Unlock()
		var once sync.Once
		done := func() {
			once.Do(func() {
				mu.Lock()
				delete(live, srv)
				mu.Unlock()
				go srv.Shutdown()
			})
		}
		conn := &smbConn{Conn: &idleConn{c, serverIdleTimeout}, done: done}
		_ = srv.ServeListener(newOneConnListener(conn, ln.Addr()))
	})
	return closerFunc(func() error {
		ln.Close()
		mu.Lock()
		for srv := range live {
			srv.Shutdown()
		}
		mu.Unlock()
		fsys.closeAll()
		return nil
	}), nil
}

// smbConn calls done once the connection fails or is closed, which ends
// its server instance.
type smbConn struct {
	net.Conn
	done func()
}

func (c *smbConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.done()
	}
	return n, err
}

func (c *smbConn) Close() error {
	c.done()
	return c.Conn.Close()
}

// oneConnListener hands out a single connection, then blocks until closed
// (the server's accept loop spins on errors, so it must not see one early).
type oneConnListener struct {
	c      net.Conn
	addr   net.Addr
	given  bool
	mu     sync.Mutex
	once   sync.Once
	closed chan struct{}
}

func newOneConnListener(c net.Conn, addr net.Addr) *oneConnListener {
	return &oneConnListener{c: c, addr: addr, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	first := !l.given
	l.given = true
	l.mu.Unlock()
	if first {
		return l.c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.addr }

// smbFS is the share: an empty directory that accepts uploads (each checked
// and stored by the server's receive on close) and holds the verdict files.
type smbFS struct {
	s *Server

	mu      sync.Mutex
	next    uint64
	handles map[vfs.VfsHandle]*smbHandle
	results map[string]*smbResult // by path, lower-cased
}

type smbKind int

const (
	smbDir smbKind = iota
	smbUpload
	smbVerdict
)

type smbHandle struct {
	kind  smbKind
	path  string
	inode uint64
	tmp   *os.File // upload
	size  int64    // upload
	data  []byte   // verdict
}

type smbResult struct {
	data  []byte
	inode uint64
	at    time.Time
}

func newSMBFS(s *Server) *smbFS {
	return &smbFS{s: s, next: 100, handles: map[vfs.VfsHandle]*smbHandle{}, results: map[string]*smbResult{}}
}

func smbPath(p string) string {
	return strings.Trim(strings.ReplaceAll(p, `\`, "/"), "/")
}

func smbAttrs(kind smbKind, size int64, inode uint64) *vfs.Attributes {
	a := &vfs.Attributes{}
	now := time.Now()
	a.SetInodeNumber(inode)
	a.SetLinkCount(1)
	a.SetSizeBytes(uint64(size))
	a.SetDiskSizeBytes(uint64((size + 4095) / 4096 * 4096))
	a.SetAccessTime(now)
	a.SetLastDataModificationTime(now)
	a.SetLastStatusChangeTime(now)
	a.SetBirthTime(now)
	if kind == smbDir {
		a.SetFileType(vfs.FileTypeDirectory)
		a.SetUnixMode(uint32(os.ModeDir | 0o755))
		a.SetPermissions(vfs.NewPermissionsFromMode(0o755))
	} else {
		a.SetFileType(vfs.FileTypeRegularFile)
		a.SetUnixMode(0o644)
		a.SetPermissions(vfs.NewPermissionsFromMode(0o644))
	}
	return a
}

func (f *smbFS) newHandle(h *smbHandle) vfs.VfsHandle {
	f.next++
	id := vfs.VfsHandle(f.next)
	if h.inode == 0 {
		h.inode = f.next
	}
	f.handles[id] = h
	return id
}

func (f *smbFS) handle(h vfs.VfsHandle) (*smbHandle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sh, ok := f.handles[h]; ok {
		return sh, nil
	}
	return nil, errors.New("bad handle")
}

// result returns the verdict file for p, dropping verdicts older than an hour.
func (f *smbFS) result(p string) *smbResult {
	for k, r := range f.results {
		if time.Since(r.at) > time.Hour {
			delete(f.results, k)
		}
	}
	return f.results[strings.ToLower(p)]
}

func (f *smbFS) closeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, h := range f.handles {
		if h.tmp != nil {
			h.tmp.Close()
			os.Remove(h.tmp.Name())
		}
		delete(f.handles, id)
	}
}

func (f *smbFS) GetAttr(h vfs.VfsHandle) (*vfs.Attributes, error) {
	if h == 0 {
		return smbAttrs(smbDir, 0, uint64(vfs.VFS_ROOT_NODE)), nil
	}
	sh, err := f.handle(h)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch sh.kind {
	case smbUpload:
		return smbAttrs(smbUpload, sh.size, sh.inode), nil
	case smbVerdict:
		return smbAttrs(smbVerdict, int64(len(sh.data)), sh.inode), nil
	}
	return smbAttrs(smbDir, 0, sh.inode), nil
}

func (f *smbFS) SetAttr(h vfs.VfsHandle, _ *vfs.Attributes) (*vfs.Attributes, error) {
	return f.GetAttr(h)
}

func (f *smbFS) StatFS(vfs.VfsHandle) (*vfs.FSAttributes, error) {
	a := &vfs.FSAttributes{}
	a.SetBlockSize(4096)
	a.SetIOSize(65536)
	a.SetBlocks(1 << 28)
	a.SetFreeBlocks(1 << 27)
	a.SetAvailableBlocks(1 << 27)
	a.SetFiles(1 << 20)
	a.SetFreeFiles(1 << 20)
	return a, nil
}

func (f *smbFS) FSync(vfs.VfsHandle) error { return nil }
func (f *smbFS) Flush(vfs.VfsHandle) error { return nil }

// Lookup reports what exists: the share root and the verdict files. An
// upload's own name never exists beforehand, so every create is a new file.
func (f *smbFS) Lookup(_ vfs.VfsHandle, name string) (*vfs.Attributes, error) {
	p := smbPath(name)
	if p == "" {
		return smbAttrs(smbDir, 0, uint64(vfs.VFS_ROOT_NODE)), nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.result(p); r != nil {
		return smbAttrs(smbVerdict, int64(len(r.data)), r.inode), nil
	}
	return nil, os.ErrNotExist
}

func (f *smbFS) Open(name string, flags int, _ int) (vfs.VfsHandle, error) {
	p := smbPath(name)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r := f.result(p); r != nil {
		return f.newHandle(&smbHandle{kind: smbVerdict, path: p, inode: r.inode, data: r.data}), nil
	}
	if flags&(os.O_WRONLY|os.O_RDWR|os.O_CREATE) == 0 {
		return 0, os.ErrNotExist
	}
	if strings.Contains(p, "/") {
		return 0, os.ErrPermission // the share has no subdirectories
	}
	dir := f.s.out
	if f.s.perMethod {
		dir = path.Join(dir, "smb")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, err
		}
	}
	tmp, err := os.CreateTemp(dir, ".transfermapexec-smb-*.part")
	if err != nil {
		f.s.logf("smb", "cannot create a temporary file: %v", err)
		return 0, os.ErrPermission
	}
	return f.newHandle(&smbHandle{kind: smbUpload, path: p, tmp: tmp}), nil
}

// Close finishes an upload: the file is checked and stored by the usual
// receiver, and the verdict is left for the client to read.
func (f *smbFS) Close(h vfs.VfsHandle) error {
	f.mu.Lock()
	sh, ok := f.handles[h]
	delete(f.handles, h)
	f.mu.Unlock()
	if !ok || sh.kind != smbUpload {
		return nil
	}
	defer func() {
		sh.tmp.Close()
		os.Remove(sh.tmp.Name())
	}()
	verdict := "OK"
	err := f.s.receive("smb", "smb:"+sh.path, io.NewSectionReader(sh.tmp, 0, sh.size))
	if err != nil {
		verdict = "ERR " + oneLine(err.Error())
	}
	f.mu.Lock()
	f.next++
	f.results[strings.ToLower(sh.path+smbResultSuffix)] = &smbResult{data: []byte(verdict + "\n"), inode: f.next, at: time.Now()}
	f.mu.Unlock()
	return nil
}

func (f *smbFS) Read(h vfs.VfsHandle, buf []byte, off uint64, _ int) (int, error) {
	sh, err := f.handle(h)
	if err != nil {
		return 0, err
	}
	switch sh.kind {
	case smbVerdict:
		if off >= uint64(len(sh.data)) {
			return 0, io.EOF
		}
		return copy(buf, sh.data[off:]), nil
	case smbUpload:
		return sh.tmp.ReadAt(buf, int64(off))
	}
	return 0, errors.New("is a directory")
}

func (f *smbFS) Write(h vfs.VfsHandle, buf []byte, off uint64, _ int) (int, error) {
	sh, err := f.handle(h)
	if err != nil {
		return 0, err
	}
	if sh.kind != smbUpload {
		return 0, os.ErrPermission
	}
	n, err := sh.tmp.WriteAt(buf, int64(off))
	f.mu.Lock()
	if end := int64(off) + int64(n); end > sh.size {
		sh.size = end
	}
	f.mu.Unlock()
	return n, err
}

func (f *smbFS) Truncate(h vfs.VfsHandle, size uint64) error {
	sh, err := f.handle(h)
	if err != nil {
		return err
	}
	if sh.kind != smbUpload {
		return os.ErrPermission
	}
	f.mu.Lock()
	sh.size = int64(size)
	f.mu.Unlock()
	return sh.tmp.Truncate(int64(size))
}

func (f *smbFS) OpenDir(name string) (vfs.VfsHandle, error) {
	if smbPath(name) != "" {
		return 0, os.ErrNotExist
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newHandle(&smbHandle{kind: smbDir, inode: uint64(vfs.VFS_ROOT_NODE)}), nil
}

func (f *smbFS) ReadDir(vfs.VfsHandle, int, int) ([]vfs.DirInfo, error) { return nil, nil }

func (f *smbFS) Mkdir(string, int) (*vfs.Attributes, error)   { return nil, os.ErrPermission }
func (f *smbFS) Readlink(vfs.VfsHandle) (string, error)       { return "", os.ErrInvalid }
func (f *smbFS) Unlink(vfs.VfsHandle) error                   { return nil }
func (f *smbFS) Rename(vfs.VfsHandle, string, int) error      { return os.ErrPermission }
func (f *smbFS) Listxattr(vfs.VfsHandle) ([]string, error)    { return nil, nil }
func (f *smbFS) Setxattr(vfs.VfsHandle, string, []byte) error { return nil }
func (f *smbFS) Removexattr(vfs.VfsHandle, string) error      { return nil }
func (f *smbFS) Getxattr(vfs.VfsHandle, string, []byte) (int, error) {
	return 0, os.ErrNotExist
}
func (f *smbFS) Symlink(vfs.VfsHandle, string, int) (*vfs.Attributes, error) {
	return nil, os.ErrPermission
}
func (f *smbFS) Link(vfs.VfsNode, vfs.VfsNode, string) (*vfs.Attributes, error) {
	return nil, os.ErrPermission
}
