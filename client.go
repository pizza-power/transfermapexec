package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type clientOpts struct {
	ports          map[string]int
	connectTimeout time.Duration
	idleTimeout    time.Duration
	timeout        time.Duration
	sni            string
	dnsDomain      string
	dnsServer      string
	verbose        bool
}

// target is one address of the server to test.
type target struct {
	host string // as given (a name or an IP): used in URLs, Host headers and SNI
	ip   net.IP // the address dialled
}

func (t target) v6() bool { return t.ip.To4() == nil }

func (t target) family() string {
	if t.v6() {
		return "IPv6"
	}
	return "IPv4"
}

func (t target) String() string {
	if t.host != t.ip.String() {
		return fmt.Sprintf("%s (%s %s)", t.host, t.family(), t.ip)
	}
	return fmt.Sprintf("%s (%s)", t.ip, t.family())
}

// attempt is one method's try at delivering the frame to one target.
type attempt struct {
	ctx      context.Context // ends on -timeout, on stalling (-idle-timeout), or on Ctrl-C
	m        *method
	opts     *clientOpts
	tgt      target
	host     string // tgt.host
	ip       string // tgt.ip as a string
	port     int
	addr     string // ip:port: what is dialled
	hostport string // host:port: what goes in URLs
	frame    *frame
	guard    *idleGuard

	// connected is set once the method has reached the server (connection
	// made, handshake done, or first reply received). Errors before that
	// point are explained as the method being blocked or the server absent.
	connected atomic.Bool
}

// result is what the client reports for one method and target.
type result struct {
	Method   string  `json:"method"`
	Target   string  `json:"target"`
	Family   string  `json:"family"`
	Endpoint string  `json:"endpoint"`
	OK       bool    `json:"ok"`
	Bytes    int64   `json:"bytes"`
	Seconds  float64 `json:"seconds"`
	Detail   string  `json:"detail,omitempty"`
	Error    string  `json:"error,omitempty"`
}

func runClient(args []string) int {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	host := fs.String("host", "", "server name or IP address, or several comma-separated (e.g. 192.168.1.50,fd00::50)")
	ipMode := fs.String("ip", "both", `address families to test: "both" (every family the server has an address for), "4" or "6"`)
	methodList := fs.String("method", "", `method(s) to use, comma-separated (see "transfermapexec methods")`)
	all := fs.Bool("all", false, "try every method, one after another, and report which ones worked")
	file := fs.String("file", "", "path to a file to send")
	text := fs.String("text", "", "text string to send")
	name := fs.String("name", "", "override the filename/label stored with the payload")
	port := fs.Int("port", 0, "port to use (only with a single -method)")
	portList := fs.String("ports", "", `per-method port overrides, e.g. "http=80,https=443,dns=53"`)
	connectTimeout := fs.Duration("connect-timeout", 5*time.Second, "how long a method may take to reach the server before it counts as blocked")
	idleTimeout := fs.Duration("idle-timeout", 15*time.Second, "abandon a transfer that makes no progress for this long")
	timeout := fs.Duration("timeout", 5*time.Minute, "hard limit on each method, start to finish")
	parallel := fs.Bool("parallel", false, "run the methods at the same time instead of one after another")
	sni := fs.String("sni", "", "server name to send in the TLS ClientHello (default: -host when it is a name)")
	dnsDomain := fs.String("dns-domain", "mt.test", "domain the DNS methods send their queries under (must match the server)")
	dnsServer := fs.String("dns-server", "", "send the dns method's queries to this resolver (host:port) instead of straight to the server")
	jsonOut := fs.Bool("json", false, "print the results as JSON")
	reportPath := fs.String("report", "", "also write an HTML report of what worked and what didn't to this file (e.g. -report report.html)")
	verbose := fs.Bool("v", false, "verbose logging")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: transfermapexec client -host HOST (-method LIST | -all) (-file PATH | -text STRING) [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nMethods and default ports:\n\n")
		printMethods(os.Stderr)
	}
	_ = fs.Parse(args)

	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
		fs.Usage()
		return 2
	}
	if fs.NArg() > 0 {
		return usageErr("unexpected argument %q", fs.Arg(0))
	}
	if *host == "" {
		return usageErr("-host is required")
	}
	if (*methodList == "") == !*all {
		return usageErr("specify exactly one of -method or -all")
	}
	if (*file == "") == (*text == "") {
		return usageErr("specify exactly one of -file or -text")
	}
	if *connectTimeout <= 0 || *idleTimeout <= 0 || *timeout <= 0 {
		return usageErr("timeouts must be positive")
	}
	if *ipMode != "both" && *ipMode != "4" && *ipMode != "6" {
		return usageErr(`-ip must be "both", "4" or "6"`)
	}

	list := *methodList
	if *all {
		list = "all"
	}
	selected, err := selectMethods(list)
	if err != nil {
		return usageErr("%v", err)
	}
	ports, err := parsePorts(*portList)
	if err != nil {
		return usageErr("%v", err)
	}
	if *port != 0 {
		if len(selected) != 1 {
			return usageErr("-port only works with a single -method; use -ports for several")
		}
		if selected[0].proto == "icmp" {
			return usageErr("icmp has no ports")
		}
		if *port < 1 || *port > 65535 {
			return usageErr("-port must be 1-65535")
		}
		ports[selected[0].name] = *port
	}

	targets, note, err := resolveTargets(*host, *ipMode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Build the frame once; every method sends the same bytes.
	var fr *frame
	if *file != "" {
		sentName := *name
		if sentName == "" {
			sentName = filepath.Base(*file)
		}
		var f *os.File
		fr, f, err = newFileFrame(*file, sentName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer f.Close()
	} else if fr, err = newTextFrame(*text, *name); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	opts := &clientOpts{
		ports:          ports,
		connectTimeout: *connectTimeout,
		idleTimeout:    *idleTimeout,
		timeout:        *timeout,
		sni:            *sni,
		dnsDomain:      strings.ToLower(strings.Trim(*dnsDomain, ".")),
		dnsServer:      *dnsServer,
		verbose:        *verbose,
	}

	// Ctrl-C stops the method in progress and skips the rest.
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel(errors.New("interrupted"))
	}()

	what := fmt.Sprintf("%s %q", fr.h.kindName(), fr.h.name)
	if fr.h.kind == typeText && fr.h.name == "" {
		what = "text"
	}
	if !*jsonOut {
		var names []string
		for _, t := range targets {
			names = append(names, t.String())
		}
		fmt.Printf("sending %s (%s, sha256 %s…) with %d method(s) to %s\n",
			what, formatBytes(int64(fr.h.payloadLen)), hex.EncodeToString(fr.h.sum[:6]), len(selected), strings.Join(names, " and "))
		if note != "" {
			fmt.Println("note:", note)
		}
		fmt.Println()
	}

	// One job per target and method, run in that order (or all at once).
	type job struct {
		t target
		m *method
	}
	var jobs []job
	for _, t := range targets {
		for _, m := range selected {
			jobs = append(jobs, job{t, m})
		}
	}
	results := make([]result, len(jobs))
	var printMu sync.Mutex
	report := func(i int, r result) {
		results[i] = r
		if !*jsonOut {
			printMu.Lock()
			fmt.Println(r.line())
			printMu.Unlock()
		}
	}
	if *parallel {
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				report(i, runAttempt(ctx, j.m, j.t, opts, fr))
			}()
		}
		wg.Wait()
	} else {
		for i, j := range jobs {
			if ctx.Err() != nil {
				report(i, result{
					Method: j.m.name, Target: j.t.ip.String(), Family: j.t.family(),
					Endpoint: endpoint(j.m, portFor(j.m, ports)),
					Error:    "skipped: " + context.Cause(ctx).Error(),
				})
				continue
			}
			report(i, runAttempt(ctx, j.m, j.t, opts, fr))
		}
	}

	failures := 0
	type summary struct {
		Target string   `json:"target"`
		Family string   `json:"family"`
		Worked []string `json:"worked"`
		Failed []string `json:"failed"`
	}
	var sums []summary
	for _, t := range targets {
		sm := summary{Target: t.ip.String(), Family: t.family(), Worked: []string{}, Failed: []string{}}
		for _, r := range results {
			if r.Target != sm.Target {
				continue
			}
			if r.OK {
				sm.Worked = append(sm.Worked, r.Method)
			} else {
				sm.Failed = append(sm.Failed, r.Method)
				failures++
			}
		}
		sums = append(sums, sm)
	}

	if *jsonOut {
		out := map[string]any{
			"host":    *host,
			"payload": map[string]any{"kind": fr.h.kindName(), "name": fr.h.name, "bytes": fr.h.payloadLen, "sha256": hex.EncodeToString(fr.h.sum[:])},
			"results": results,
			"summary": sums,
		}
		if note != "" {
			out["note"] = note
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		fmt.Println()
		width := 0
		for _, sm := range sums {
			width = max(width, len(sm.Family)+1+len(sm.Target))
		}
		for _, sm := range sums {
			n := len(sm.Worked) + len(sm.Failed)
			prefix := ""
			if len(sums) > 1 {
				prefix = fmt.Sprintf("%-*s  ", width, sm.Family+" "+sm.Target)
			}
			fmt.Printf("%sworked (%d/%d): %s\n", prefix, len(sm.Worked), n, joinOrNone(sm.Worked))
			fmt.Printf("%sfailed (%d/%d): %s\n", strings.Repeat(" ", len(prefix)), len(sm.Failed), n, joinOrNone(sm.Failed))
		}
	}

	if *reportPath != "" {
		if err := writeHTMLReport(*reportPath, *host, fr.h, note, results, targets, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "error: writing HTML report:", err)
		} else if *jsonOut {
			fmt.Fprintln(os.Stderr, "wrote HTML report to", *reportPath)
		} else {
			fmt.Printf("\nwrote HTML report to %s\n", *reportPath)
		}
	}

	if failures > 0 {
		return 1
	}
	return 0
}

// resolveTargets turns -host into the addresses to test. IP addresses are
// used as given; names are resolved, keeping the first address of each
// family -ip asks for. The note says which family is not being tested, and
// how to test it.
func resolveTargets(hosts, mode string) ([]target, string, error) {
	var out []target
	for _, h := range strings.Split(hosts, ",") {
		h = strings.Trim(strings.TrimSpace(h), "[]")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			t := target{host: ip.String(), ip: ip}
			if (mode == "4" && t.v6()) || (mode == "6" && !t.v6()) {
				return nil, "", fmt.Errorf("%s is an %s address, but -ip %s was given", h, t.family(), mode)
			}
			out = append(out, t)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", h)
		cancel()
		if err != nil {
			return nil, "", fmt.Errorf("cannot resolve %s: %w", h, err)
		}
		var v4, v6 net.IP
		for _, ip := range ips {
			if ip.To4() != nil && v4 == nil {
				v4 = ip
			} else if ip.To4() == nil && v6 == nil {
				v6 = ip
			}
		}
		found := 0
		if v4 != nil && mode != "6" {
			out = append(out, target{host: h, ip: v4})
			found++
		}
		if v6 != nil && mode != "4" {
			out = append(out, target{host: h, ip: v6})
			found++
		}
		if found == 0 {
			want := map[string]string{"4": "IPv4", "6": "IPv6", "both": "IP"}[mode]
			return nil, "", fmt.Errorf("%s has no %s address", h, want)
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("-host has no addresses")
	}

	has4, has6 := false, false
	for _, t := range out {
		has4 = has4 || !t.v6()
		has6 = has6 || t.v6()
	}
	note := ""
	switch {
	case has4 && !has6 && mode == "both":
		note = "IPv6 is not being tested: the server has no IPv6 address here. To test it, add the server's IPv6 address to -host (e.g. -host 192.168.1.50,fd00::50)."
	case has6 && !has4 && mode == "both":
		note = "IPv4 is not being tested: add the server's IPv4 address to -host to test it too."
	}
	return out, note, nil
}

// runAttempt runs one method against one target with its timeouts and turns
// the outcome into a result.
func runAttempt(parent context.Context, m *method, t target, opts *clientOpts, fr *frame) result {
	port := portFor(m, opts.ports)
	res := result{Method: m.name, Target: t.ip.String(), Family: t.family(), Endpoint: endpoint(m, port), Bytes: int64(fr.h.payloadLen)}
	if m.name == "dns" && opts.dnsServer != "" {
		res.Endpoint = "via " + opts.dnsServer
	}

	ctx, cancelTimeout := context.WithTimeoutCause(parent, opts.timeout,
		fmt.Errorf("not finished after %s (-timeout)", opts.timeout))
	defer cancelTimeout()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	a := &attempt{
		ctx:      ctx,
		m:        m,
		opts:     opts,
		tgt:      t,
		host:     t.host,
		ip:       t.ip.String(),
		port:     port,
		addr:     net.JoinHostPort(t.ip.String(), strconv.Itoa(port)),
		hostport: net.JoinHostPort(t.host, strconv.Itoa(port)),
		frame:    fr,
	}
	// Reaching the server is bounded by -connect-timeout inside each method;
	// the guard allows for that before it starts counting idle time.
	a.guard = newIdleGuard(opts.connectTimeout+opts.idleTimeout, opts.idleTimeout, cancel)
	defer a.guard.stop()

	start := time.Now()
	detail, err := safeSend(a)
	res.Seconds = time.Since(start).Seconds()
	if err != nil && ctx.Err() != nil {
		// The timeout, the idle guard or Ctrl-C ended the attempt; that is
		// the real reason, not the "use of closed connection" it caused.
		err = context.Cause(ctx)
	}
	res.Detail = detail
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK = true
	}
	return res
}

// safeSend runs the method's sender, turning a panic into a failure so one
// broken method cannot stop -all.
func safeSend(a *attempt) (detail string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return a.m.send(a)
}

// source returns a fresh reader over the frame; reading from it counts as
// progress for the idle guard.
func (a *attempt) source() io.Reader { return a.guard.reader(a.frame.open()) }

func (a *attempt) logf(format string, args ...any) {
	if a.opts.verbose {
		fmt.Fprintf(os.Stderr, "[%s %s] "+format+"\n", append([]any{a.m.name, a.tgt.family()}, args...)...)
	}
}

// sniName is the server name for TLS: -sni, else -host when it is a name.
func (a *attempt) sniName() string {
	if a.opts.sni != "" {
		return a.opts.sni
	}
	if net.ParseIP(a.host) == nil {
		return a.host
	}
	return ""
}

// uploadName is the payload's name, made safe for protocols that carry a
// filename of their own (FTP, TFTP, SMB, SFTP, email).
func (a *attempt) uploadName() string {
	name := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, a.frame.h.name)
	if name == "" || name == "." || name == ".." {
		return "message.txt"
	}
	return name
}

// dial connects to the method's port over network ("tcp" or "udp"), within
// -connect-timeout.
func (a *attempt) dial(network string) (net.Conn, error) {
	d := net.Dialer{Timeout: a.opts.connectTimeout}
	c, err := d.DialContext(a.ctx, network, a.addr)
	if err != nil {
		return nil, a.unreachable(err)
	}
	if network == "tcp" {
		a.connected.Store(true)
		a.logf("connected to %s", c.RemoteAddr())
	}
	return c, nil
}

func (a *attempt) dialTCP() (net.Conn, error) { return a.dial("tcp") }

// dialContext is a DialContext for HTTP transports: requests go to
// hostport, but the connection is made to the target's address, so the test
// uses exactly the address family it reports.
func (a *attempt) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr == a.hostport {
		addr = a.addr
	}
	return (&net.Dialer{Timeout: a.opts.connectTimeout}).DialContext(ctx, network, addr)
}

// closeOnDone closes c when the attempt's context ends, unblocking any read
// or write in progress. The returned func stops the watch.
func closeOnDone(a *attempt, c io.Closer) func() bool {
	return context.AfterFunc(a.ctx, func() { c.Close() })
}

// handshake runs f (a protocol handshake on the freshly dialed c) with
// -connect-timeout as its deadline.
func (a *attempt) handshake(c net.Conn, f func() error) error {
	_ = c.SetDeadline(time.Now().Add(a.opts.connectTimeout))
	err := f()
	_ = c.SetDeadline(time.Time{})
	if err != nil && isTimeout(err) && a.ctx.Err() == nil {
		return fmt.Errorf("connected, but the handshake got no answer within %s (something on the path is holding it?)", a.opts.connectTimeout)
	}
	return err
}

// unreachable explains a failure to reach the server in terms of what it most
// likely means for the method.
func (a *attempt) unreachable(err error) error {
	if a.ctx.Err() != nil {
		return context.Cause(a.ctx)
	}
	var ce *contactError
	if errors.As(err, &ce) {
		return ce.err
	}
	where := endpoint(a.m, a.port)
	if a.m.name == "webrtc" {
		where = fmt.Sprintf("tcp/%d (signaling)", a.port)
	}
	switch {
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		strings.Contains(err.Error(), "operation not permitted"):
		// Linux reports a packet dropped by the local firewall's OUTPUT
		// rules as EPERM on send (QUIC only passes the text along).
		return fmt.Errorf("this machine refused to send to %s (operation not permitted): a firewall on the client itself blocks it", where)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("connection refused on %s: nothing listening there, or a firewall rejected it", where)
	case isTimeout(err):
		return fmt.Errorf("no answer on %s within %s (-connect-timeout): dropped by a firewall, or the server is not listening", where, a.opts.connectTimeout)
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL):
		return fmt.Errorf("no route to %s over %s: %v", a.ip, a.tgt.family(), err)
	}
	return err
}

// contactError is a failure that shows, before the first answer, that the
// method cannot work (a proxy's block page, a DNS server refusing the
// domain), so there is no point waiting out -connect-timeout.
type contactError struct{ err error }

func (e *contactError) Error() string { return e.err.Error() }
func (e *contactError) Unwrap() error { return e.err }

// line renders a result as one row of the client's report.
func (r result) line() string {
	status, info := "ok  ", r.Detail
	rate := ""
	if r.OK {
		if r.Seconds > 0 {
			rate = formatBytes(int64(float64(r.Bytes)/r.Seconds)) + "/s"
		}
	} else {
		status, info = "FAIL", r.Error
	}
	fam := "v4"
	if r.Family == "IPv6" {
		fam = "v6"
	}
	return fmt.Sprintf("  %s  %-11s %s  %-13s %7s %11s  %s", status, r.Method, fam, r.Endpoint, formatDuration(r.Seconds), rate, info)
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func formatDuration(sec float64) string {
	d := time.Duration(sec * float64(time.Second))
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, " ")
}
