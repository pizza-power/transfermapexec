package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

// Server holds what every method's listener shares: where and how to store
// what arrives, the TLS certificate, and the log.
type Server struct {
	out         string
	overwrite   bool
	perMethod   bool
	verbose     bool
	logger      *log.Logger
	cert        tls.Certificate
	dnsDomain   string
	ftpPasvPort int
	bind        string
	webrtcPort  int
	webrtcIPs   []string
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	methodList := fs.String("methods", "all", `methods to serve, comma-separated, or "all"`)
	bind := fs.String("bind", "", "IP address to listen on (default: all interfaces)")
	portList := fs.String("ports", "", `per-method port overrides, e.g. "http=80,https=443,dns=53"`)
	outDir := fs.String("out", "received", "directory to write received files into")
	overwrite := fs.Bool("overwrite", true, "replace an existing file of the same name; with -overwrite=false a numeric suffix is added instead (report.1.pdf)")
	perMethod := fs.Bool("per-method", false, "store each method's copy under OUT/<method>/ instead of all in OUT")
	logPath := fs.String("log", "transfermapexec-server.log", "path to the server log file")
	dnsDomain := fs.String("dns-domain", "mt.test", "domain the dns method's queries arrive under (must match the client)")
	ftpPasv := fs.Int("ftp-pasv-port", 0, "fixed port for FTP passive-mode data connections (default: any free port)")
	webrtcPort := fs.Int("webrtc-port", 3479, "UDP port for WebRTC media (ICE); signaling goes over the webrtc method's HTTPS port")
	webrtcIP := fs.String("webrtc-ip", "", "IP address(es) to advertise to WebRTC clients, comma-separated, when the server is behind NAT (default: its own addresses)")
	verbose := fs.Bool("v", false, "verbose logging (per-connection detail)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: transfermapexec server [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nMethods and default ports:\n\n")
		printMethods(os.Stderr)
	}
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", fs.Arg(0))
		os.Exit(2)
	}

	selected, err := selectMethods(*methodList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	ports, err := parsePorts(*portList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if *bind != "" && net.ParseIP(*bind) == nil {
		fmt.Fprintf(os.Stderr, "error: -bind must be an IP address, got %q\n", *bind)
		os.Exit(2)
	}
	if *ftpPasv < 0 || *ftpPasv > 65535 {
		fmt.Fprintln(os.Stderr, "error: -ftp-pasv-port must be 0-65535")
		os.Exit(2)
	}
	if *webrtcPort < 1 || *webrtcPort > 65535 {
		fmt.Fprintln(os.Stderr, "error: -webrtc-port must be 1-65535")
		os.Exit(2)
	}
	var webrtcIPs []string
	for _, ip := range strings.Split(*webrtcIP, ",") {
		if ip = strings.TrimSpace(ip); ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			fmt.Fprintf(os.Stderr, "error: -webrtc-ip: %q is not an IP address\n", ip)
			os.Exit(2)
		}
		webrtcIPs = append(webrtcIPs, ip)
	}

	// Log to stdout and, if possible, to a log file as well.
	logw := io.Writer(os.Stdout)
	if f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot open log file %q: %v (logging to stdout only)\n", *logPath, err)
	} else {
		defer f.Close()
		logw = io.MultiWriter(os.Stdout, f)
	}
	logger := log.New(logw, "", log.LstdFlags)

	// Prepare the output directory; fall back to the current directory.
	dir := *outDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Printf("warning: cannot create output dir %q: %v (using current directory)", dir, err)
		dir = "."
	}

	cert, err := newSelfSignedCert()
	if err != nil {
		logger.Fatalf("tls setup failed: %v", err)
	}

	s := &Server{
		out:         dir,
		overwrite:   *overwrite,
		perMethod:   *perMethod,
		verbose:     *verbose,
		logger:      logger,
		cert:        cert,
		dnsDomain:   strings.ToLower(strings.Trim(*dnsDomain, ".")),
		ftpPasvPort: *ftpPasv,
		bind:        *bind,
		webrtcPort:  *webrtcPort,
		webrtcIPs:   webrtcIPs,
	}

	mode := "overwriting same-named files"
	if !s.overwrite {
		mode = "keeping same-named files (numeric suffix)"
	}
	if s.perMethod {
		mode += ", one subdirectory per method"
	}
	logger.Printf("writing files to %q (%s); log %q", dir, mode, *logPath)

	// Group the selected methods by listener and port: methods sharing both
	// (https, doh, grpc, ws and webrtc on one port, say) get one listener.
	type groupKey struct {
		listener string
		port     int
	}
	var order []groupKey
	groups := map[groupKey][]*method{}
	for _, m := range selected {
		k := groupKey{m.listenerName(), portFor(m, ports)}
		if m.proto == "icmp" {
			k.port = 0
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], m)
	}

	// Start every listener. One that cannot start (port in use, no
	// permission for ICMP, ...) is reported and the rest carry on.
	var closers []io.Closer
	var status bytes.Buffer
	tw := tabwriter.NewWriter(&status, 0, 0, 2, ' ', 0)
	started := 0
	for _, k := range order {
		group := groups[k]
		m0 := group[0]
		on := methodSet{}
		for _, m := range group {
			on[m.name] = true
		}
		var addr string
		if m0.proto == "icmp" {
			addr = *bind
		} else {
			addr = net.JoinHostPort(*bind, strconv.Itoa(k.port))
		}
		shadowed := m0.proto == "tcp" && portTakenLocally(*bind, k.port)
		c, err := m0.serve(s, addr, on)
		var partial partialStart
		if errors.As(err, &partial) {
			err = nil // the listener is up; only some of its methods failed
		}
		for i, m := range group {
			if err != nil {
				fmt.Fprintf(tw, "  %s\tNOT STARTED\t%v\n", m.name, err)
				continue
			}
			if perr, ok := partial[m.name]; ok {
				fmt.Fprintf(tw, "  %s\tNOT STARTED\t%v\n", m.name, perr)
				continue
			}
			var notes []string
			if i > 0 {
				notes = append(notes, "shared with "+group[0].name)
			}
			if shadowed && i == 0 {
				notes = append(notes, "warning: another program already accepts connections on this port on 127.0.0.1, so local clients reach it instead; remote clients may too. Pick another port with -ports")
			}
			switch {
			case m.proto == "icmp" && (runtime.GOOS == "darwin" || strings.HasSuffix(runtime.GOOS, "bsd")):
				notes = append(notes, "warning: this OS answers pings in the kernel and may never pass them to transfermapexec; use a Linux server for icmp")
			case m.name == "dns" || m.name == "doh" || m.name == "dot" || m.name == "dns-tcp":
				notes = append(notes, "queries under *."+s.dnsDomain)
			case m.name == "webrtc":
				notes = append(notes, fmt.Sprintf("signaling here, media on udp/%d", s.webrtcPort))
			}
			where := m.proto + " " + addr
			if m.proto == "icmp" {
				where = "icmp + icmpv6"
			}
			note := ""
			if len(notes) > 0 {
				note = "\t(" + strings.Join(notes, "; ") + ")"
			}
			fmt.Fprintf(tw, "  %s\tlistening on %s%s\n", m.name, where, note)
			started++
		}
		if err == nil {
			closers = append(closers, c)
		}
	}
	tw.Flush()
	for _, line := range strings.Split(strings.TrimRight(status.String(), "\n"), "\n") {
		logger.Print(line)
	}
	if started == 0 {
		logger.Fatalf("no method could be started")
	}
	logger.Printf("ready: %d of %d methods listening (Ctrl-C to stop)", started, len(selected))

	// Run until Ctrl-C / SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	logger.Printf("shutdown requested, closing listeners...")
	for _, c := range closers {
		_ = c.Close()
	}
	logger.Printf("server stopped")
}

// partialStart is returned by a shared listener that started, but without
// some of its methods (webrtc when its UDP port is taken, say). It maps each
// method that could not start to the reason.
type partialStart map[string]error

func (p partialStart) Error() string {
	var parts []string
	for name, err := range p {
		parts = append(parts, name+": "+err.Error())
	}
	return strings.Join(parts, "; ")
}

// err returns p as an error, or nil if every method started.
func (p partialStart) err() error {
	if len(p) == 0 {
		return nil
	}
	return p
}

// portTakenLocally reports whether something already accepts TCP connections
// on port before we listen on it. Some systems (macOS, BSD) let a wildcard
// listener share a port with another program's address-specific one, which
// then silently takes the connections meant for us.
func portTakenLocally(bind string, port int) bool {
	host := "127.0.0.1"
	if ip := net.ParseIP(bind); ip != nil && !ip.IsUnspecified() {
		host = bind
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func (s *Server) logf(method, format string, args ...any) {
	s.logger.Printf("[%s] "+format, append([]any{method}, args...)...)
}

// debugf logs per-connection detail, only shown with -v.
func (s *Server) debugf(method, format string, args ...any) {
	if s.verbose {
		s.logf(method, format, args...)
	}
}

// receive reads one frame from r and stores it: a file goes to disk, text is
// printed and logged. It returns nil only once the payload has arrived in full
// and matches its SHA-256; otherwise the error says why, and its text is sent
// back to the client as the reason the transfer failed.
func (s *Server) receive(method, remote string, r io.Reader) error {
	h, err := readHeader(r)
	if err != nil {
		s.logf(method, "bad transfer from %s: %v", remote, err)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("data ended before the header was complete")
		}
		return fmt.Errorf("bad header: %v", err)
	}
	if h.kind == typeText {
		return s.storeText(method, remote, h, r)
	}
	return s.storeFile(method, remote, h, r)
}

// storeFile writes a file payload to a temporary file next to its
// destination, checks it, then renames it into place. A transfer that fails
// part-way therefore never replaces a good copy from an earlier one.
func (s *Server) storeFile(method, remote string, h header, r io.Reader) error {
	dir := s.out
	if s.perMethod {
		dir = filepath.Join(dir, method)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.logf(method, "cannot create %q: %v", dir, err)
			return errors.New("server cannot create its output directory")
		}
	}

	tmp, err := os.CreateTemp(dir, ".transfermapexec-*.part")
	if err != nil {
		s.logf(method, "cannot create a file for %q from %s: %v", h.name, remote, err)
		return errors.New("server cannot create a file")
	}
	tmpName := tmp.Name()
	stored := false
	defer func() {
		if !stored {
			os.Remove(tmpName)
		}
	}()

	sum := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, sum), io.LimitReader(r, int64(h.payloadLen)))
	closeErr := tmp.Close()
	switch {
	case copyErr != nil:
		s.logf(method, "error receiving file %q from %s after %d of %d bytes: %v", h.name, remote, n, h.payloadLen, copyErr)
		return fmt.Errorf("receiving failed after %d of %d bytes: %v", n, h.payloadLen, copyErr)
	case uint64(n) != h.payloadLen:
		s.logf(method, "incomplete file %q from %s: got %d of %d bytes", h.name, remote, n, h.payloadLen)
		return fmt.Errorf("incomplete: got %d of %d bytes", n, h.payloadLen)
	case closeErr != nil:
		s.logf(method, "error writing %q: %v", tmpName, closeErr)
		return errors.New("server failed writing the file")
	case !bytes.Equal(sum.Sum(nil), h.sum[:]):
		s.logf(method, "file %q from %s failed its SHA-256 check (%d bytes): discarded", h.name, remote, n)
		return errors.New("SHA-256 mismatch: the data was altered in transit")
	}
	_ = os.Chmod(tmpName, 0o644)

	dest := filepath.Join(dir, sanitizeName(h.name))
	if !s.overwrite {
		f, err := createUnique(dest)
		if err != nil {
			s.logf(method, "cannot create %q: %v", dest, err)
			return errors.New("server cannot create a file")
		}
		dest = f.Name()
		f.Close()
	}
	if err := os.Rename(tmpName, dest); err != nil {
		s.logf(method, "cannot move received file into place at %q: %v", dest, err)
		return errors.New("server cannot store the file")
	}
	stored = true
	s.logf(method, "received file from %s: %q (%d bytes, sha256 ok) -> %s", remote, h.name, n, dest)
	return nil
}

// storeText prints and logs a text payload.
func (s *Server) storeText(method, remote string, h header, r io.Reader) error {
	total := int64(h.payloadLen)
	shown := min(total, maxTextDisplay)
	sum := sha256.New()

	data, err := io.ReadAll(io.TeeReader(io.LimitReader(r, shown), sum))
	got := int64(len(data))
	if err == nil {
		// Consume anything beyond the display cap so the payload is still
		// received, and checked, in full.
		var rest int64
		rest, err = io.Copy(sum, io.LimitReader(r, total-shown))
		got += rest
	}
	switch {
	case err != nil:
		s.logf(method, "error receiving text from %s after %d of %d bytes: %v", remote, got, total, err)
		return fmt.Errorf("receiving failed after %d of %d bytes: %v", got, total, err)
	case got != total:
		s.logf(method, "incomplete text from %s: got %d of %d bytes", remote, got, total)
		return fmt.Errorf("incomplete: got %d of %d bytes", got, total)
	case !bytes.Equal(sum.Sum(nil), h.sum[:]):
		s.logf(method, "text from %s failed its SHA-256 check: discarded", remote)
		return errors.New("SHA-256 mismatch: the data was altered in transit")
	}

	label := ""
	if h.name != "" {
		label = fmt.Sprintf(" [label: %s]", h.name)
	}
	trunc := ""
	if shown < total {
		trunc = " (truncated for display)"
	}
	s.logf(method, "received text from %s (%d bytes, sha256 ok)%s%s:\n---- begin text ----\n%s\n---- end text ----",
		remote, total, label, trunc, data)
	return nil
}

// sanitizeName reduces a possibly hostile or cross-platform path to a safe
// base filename so a client cannot write outside the output directory.
func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || name == "/" {
		return fmt.Sprintf("received-%d.bin", time.Now().UnixNano())
	}
	return name
}

// createUnique creates the file p, or if p already exists, p with a numeric
// suffix inserted before the extension (e.g. file.1.bin). Creation is
// exclusive, so an existing file is never overwritten.
func createUnique(p string) (*os.File, error) {
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	cand := p
	for i := 1; ; i++ {
		f, err := os.OpenFile(cand, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if !errors.Is(err, os.ErrExist) {
			return f, err
		}
		cand = fmt.Sprintf("%s.%d%s", base, i, ext)
	}
}
