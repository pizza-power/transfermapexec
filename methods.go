package main

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
)

// methodSet names the methods a shared listener should answer for.
type methodSet map[string]bool

// method is one way of getting a frame from the client to the server.
type method struct {
	name  string
	proto string // what the server listens on: "tcp", "udp" or "icmp"
	port  int    // default port (unused for icmp)
	desc  string

	// listener names the server-side listener the method arrives on.
	// Methods with the same listener and port share one: https, doh, grpc,
	// ws and webrtc can all be served by a single HTTPS server, the way they
	// would be on port 443. Empty means a listener of its own.
	listener string

	// send delivers a.frame to the server and returns a short note on how
	// it went (negotiated protocol, chunk counts, ...). A nil error means the
	// server confirmed it stored the data intact.
	send func(a *attempt) (detail string, err error)

	// serve starts a listener on addr for the methods in on (all of which
	// share this listener) and returns once it is up; connections are
	// handled in the background until the Closer is closed.
	serve func(s *Server, addr string, on methodSet) (io.Closer, error)
}

func (m *method) listenerName() string {
	if m.listener != "" {
		return m.listener
	}
	return m.name
}

// methods lists every method, in the order -all tries them: TCP-based
// methods first, then UDP-based, then ICMP.
var methods []*method

func init() {
	methods = []*method{
		// Plain streams.
		{name: "tcp", proto: "tcp", port: 9001, desc: "raw TCP stream", send: sendTCP, serve: serveTCP},
		{name: "tls", proto: "tcp", port: 9002, desc: "raw TLS 1.3 stream (no HTTP inside)", send: sendTLS, serve: serveTLS},

		// Cleartext web.
		{name: "http", proto: "tcp", port: 8080, desc: "HTTP POST, cleartext", send: sendHTTP, serve: serveHTTP},
		{name: "http-query", proto: "tcp", port: 8080, listener: "http", desc: "many HTTP GETs, data in the URL query string (no body)", send: sendHTTPQuery, serve: serveHTTP},
		{name: "http-cookie", proto: "tcp", port: 8080, listener: "http", desc: "many HTTP GETs, data in a Cookie header (no body)", send: sendHTTPCookie, serve: serveHTTP},
		{name: "http-header", proto: "tcp", port: 8080, listener: "http", desc: "many HTTP GETs, data in an Authorization: Bearer header (no body)", send: sendHTTPHeader, serve: serveHTTP},

		// Over TLS, sharing one HTTPS server when given the same port.
		{name: "https", proto: "tcp", port: 8443, listener: "https", desc: "HTTPS POST (HTTP/2 when negotiated)", send: sendHTTPS, serve: serveHTTPS},
		{name: "doh", proto: "tcp", port: 8443, listener: "https", desc: "DNS-over-HTTPS (RFC 8484), data in the query names", send: sendDoH, serve: serveHTTPS},
		{name: "grpc", proto: "tcp", port: 50051, listener: "https", desc: "gRPC client-streaming call over HTTP/2 + TLS", send: sendGRPC, serve: serveHTTPS},
		{name: "ws", proto: "tcp", port: 4433, listener: "https", desc: "WebSocket over TLS (wss://)", send: sendWS, serve: serveHTTPS},

		// Application protocols.
		{name: "ssh", proto: "tcp", port: 2222, listener: "ssh", desc: "SSH session, data piped to a remote command's stdin", send: sendSSH, serve: serveSSH},
		{name: "sftp", proto: "tcp", port: 2222, listener: "ssh", desc: "SFTP upload over SSH", send: sendSFTP, serve: serveSSH},
		{name: "smtp", proto: "tcp", port: 2525, desc: "email with the data as a base64 attachment", send: sendSMTP, serve: serveSMTP},
		{name: "ftp", proto: "tcp", port: 2121, desc: "FTP upload (STOR) in passive mode", send: sendFTP, serve: serveFTP},
		{name: "smb", proto: "tcp", port: 10445, desc: "SMB2/3 file write to a share, NTLM login", send: sendSMB, serve: serveSMB},
		{name: "mqtt", proto: "tcp", port: 1883, desc: "MQTT 3.1.1 publishes (QoS 1) to a broker", send: sendMQTT, serve: serveMQTT},
		{name: "irc", proto: "tcp", port: 6667, desc: "IRC channel messages, data base64-encoded", send: sendIRC, serve: serveIRC},
		{name: "xmpp", proto: "tcp", port: 5222, desc: "XMPP with STARTTLS, In-Band Bytestream (XEP-0047)", send: sendXMPP, serve: serveXMPP},
		{name: "dot", proto: "tcp", port: 10853, desc: "DNS-over-TLS (RFC 7858), data in the query names", send: sendDoT, serve: serveDoT},
		{name: "dns-tcp", proto: "tcp", port: 5300, desc: "DNS over TCP, data in the query names", send: sendDNSTCP, serve: serveDNSTCP},
		{name: "webrtc", proto: "tcp", port: 8443, listener: "https", desc: "WebRTC data channel (ICE/DTLS/SCTP over UDP); set up over HTTPS", send: sendWebRTC, serve: serveHTTPS},

		// UDP.
		{name: "quic", proto: "udp", port: 4433, desc: "raw QUIC stream", send: sendQUIC, serve: serveQUIC},
		{name: "http3", proto: "udp", port: 8443, desc: "HTTP/3 POST over QUIC", send: sendHTTP3, serve: serveHTTP3},
		{name: "udp", proto: "udp", port: 9003, desc: "raw UDP datagrams, acknowledged and resent", send: sendUDP, serve: serveUDP},
		{name: "tftp", proto: "udp", port: 6969, desc: "TFTP write request (octet mode, blksize option)", send: sendTFTP, serve: serveTFTP},
		{name: "dns", proto: "udp", port: 5300, desc: "DNS TXT queries, data base32-encoded in the query name", send: sendDNS, serve: serveDNS},
		{name: "ntp", proto: "udp", port: 10123, desc: "NTPv4 client requests, data in an extension field", send: sendNTP, serve: serveNTP},
		{name: "syslog", proto: "udp", port: 10514, desc: "RFC 5424 syslog messages, data base64-encoded", send: sendSyslog, serve: serveSyslog},
		{name: "snmp", proto: "udp", port: 10162, desc: "SNMPv2c informs (acknowledged traps), data in a varbind", send: sendSNMP, serve: serveSNMP},
		{name: "stun", proto: "udp", port: 3478, listener: "stun", desc: "STUN Binding requests, data in an attribute", send: sendSTUN, serve: serveSTUN},
		{name: "turn", proto: "udp", port: 3478, listener: "stun", desc: "TURN allocation and ChannelData, as a call relay uses", send: sendTURN, serve: serveSTUN},

		// ICMP.
		{name: "icmp", proto: "icmp", desc: "ICMP / ICMPv6 echo (ping) requests, data in the payload", send: sendICMP, serve: serveICMP},
	}
}

func methodNames() []string {
	names := make([]string, len(methods))
	for i, m := range methods {
		names[i] = m.name
	}
	return names
}

func lookupMethod(name string) *method {
	for _, m := range methods {
		if m.name == name {
			return m
		}
	}
	return nil
}

// selectMethods parses a comma-separated method list; "all" selects every
// method. Methods come back in the order given, without duplicates.
func selectMethods(list string) ([]*method, error) {
	if strings.TrimSpace(strings.ToLower(list)) == "all" {
		return methods, nil
	}
	var out []*method
	for _, name := range strings.Split(list, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		m := lookupMethod(name)
		if m == nil {
			return nil, fmt.Errorf("unknown method %q (available: %s)", name, strings.Join(methodNames(), ", "))
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no methods given")
	}
	return out, nil
}

// parsePorts parses per-method port overrides such as "http=80,dns=53".
func parsePorts(s string) (map[string]int, error) {
	ports := map[string]int{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, val, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("bad port override %q, want method=port", kv)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		m := lookupMethod(name)
		if m == nil {
			return nil, fmt.Errorf("bad port override %q: unknown method %q", kv, name)
		}
		if m.proto == "icmp" {
			return nil, fmt.Errorf("bad port override %q: icmp has no ports", kv)
		}
		port, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad port override %q: port must be 1-65535", kv)
		}
		ports[name] = port
	}
	return ports, nil
}

func portFor(m *method, overrides map[string]int) int {
	if p, ok := overrides[m.name]; ok {
		return p
	}
	return m.port
}

// endpoint renders where a method goes, e.g. "tcp/8443" or "icmp".
func endpoint(m *method, port int) string {
	switch {
	case m.proto == "icmp":
		return "icmp"
	case m.name == "webrtc":
		return fmt.Sprintf("tcp/%d+udp", port) // signaling, then ICE on the server's -webrtc-port
	}
	return fmt.Sprintf("%s/%d", m.proto, port)
}

func printMethods(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "METHOD\tDEFAULT\tDESCRIPTION")
	for _, m := range methods {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.name, endpoint(m, m.port), m.desc)
	}
	tw.Flush()
	fmt.Fprint(w, `
Ports can be changed with -ports on both sides, e.g. -ports "http=80,https=443,dns=53".
Methods given the same port share one listener where they can (https, doh, grpc, ws
and webrtc on one HTTPS server; the http-* methods with http; sftp with ssh; turn with stun).
webrtc's media goes over UDP to the server's -webrtc-port (default 3479).
The icmp method needs root (or CAP_NET_RAW) on a Linux server.
`)
}
