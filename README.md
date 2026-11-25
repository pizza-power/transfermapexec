# transfermapexec

A client/server tool in Go for testing which ways data can get from one
machine to another. The **client** sends a file or a text string to the
**server** over any of **32 network methods**, or all of them in turn with
`-all`, over **IPv4 and IPv6**, and reports which methods got the data through.


- Single binary, three subcommands: `server`, `client`, `methods`.
- The server listens on every method at once. One that can't start (port in
  use, no permission for ICMP) is reported, and the rest carry on.
- Every transfer carries a SHA-256 of its payload. The server confirms
  delivery only after the data it stored matches, so **"worked" means the bytes
  arrived intact**, not just that a connection opened.
- Each method speaks its real protocol, as Wireshark identifies it: SMB2 with
  NTLMSSP, SMTP with a MIME message, SNMPv2c informs, NTPv4, TURN with
  long-term credentials, WebRTC (ICE, DTLS, SCTP), and so on. 
- A blocked method fails within `-connect-timeout` (default 5s), and `-all`
  moves on.
- Pure Go, no cgo. Static binaries for Linux, Windows and macOS.



## Methods

| Method | Default | Standard | How the data travels |
|---|---|---|---|
| **Plain** | | | |
| `tcp` | tcp/9001 | | raw TCP stream |
| `tls` | tcp/9002 | | raw TLS 1.3 stream (no HTTP inside) |
| `udp` | udp/9003 | | raw UDP datagrams, acknowledged and resent |
| **Web** | | | |
| `http` | tcp/8080 | 80 | HTTP POST, cleartext |
| `http-query` | tcp/8080 | 80 | many GETs, data in the URL query string (no body) |
| `http-cookie` | tcp/8080 | 80 | many GETs, data in a `Cookie` header (no body) |
| `http-header` | tcp/8080 | 80 | many GETs, data in an `Authorization: Bearer` header (no body) |
| `https` | tcp/8443 | 443 | HTTPS POST (HTTP/2) |
| `ws` | tcp/4433 | 443 | WebSocket over TLS (`wss://`) |
| `grpc` | tcp/50051 | 443 | gRPC client-streaming call (HTTP/2 + TLS) |
| `http3` | udp/8443 | 443 | HTTP/3 POST over QUIC |
| `quic` | udp/4433 | | raw QUIC stream |
| **DNS tunnelling** | | | |
| `dns` | udp/5300 | 53 | TXT queries, data base32-encoded in the query name |
| `dns-tcp` | tcp/5300 | 53 | the same over TCP |
| `dot` | tcp/10853 | 853 | the same over DNS-over-TLS (RFC 7858) |
| `doh` | tcp/8443 | 443 | the same over DNS-over-HTTPS (RFC 8484, HTTP/2) |
| **File transfer and remote access** | | | |
| `ssh` | tcp/2222 | 22 | SSH session, data piped to a remote command's stdin |
| `sftp` | tcp/2222 | 22 | SFTP upload |
| `ftp` | tcp/2121 | 21 | FTP upload (`STOR`), passive mode |
| `tftp` | udp/6969 | 69 | TFTP write request, blksize option |
| `smb` | tcp/10445 | 445 | SMB2/3 file write to a share, NTLMv2 login |
| **Messaging** | | | |
| `smtp` | tcp/2525 | 25 | email with the data as a base64 attachment |
| `mqtt` | tcp/1883 | 1883 | MQTT 3.1.1 publishes (QoS 1) to a broker |
| `irc` | tcp/6667 | 6667 | IRC channel messages |
| `xmpp` | tcp/5222 | 5222 | XMPP with STARTTLS, In-Band Bytestream (XEP-0047) |
| **Monitoring** | | | |
| `ntp` | udp/10123 | 123 | NTPv4 client requests, data in an extension field |
| `syslog` | udp/10514 | 514 | RFC 5424 syslog messages |
| `snmp` | udp/10162 | 162 | SNMPv2c informs (acknowledged traps), data in a varbind |
| **Real-time / video calls** | | | |
| `stun` | udp/3478 | 3478 | STUN Binding requests, data in an attribute |
| `turn` | udp/3478 | 3478 | TURN allocation, then ChannelData, as a call relay uses |
| `webrtc` | tcp/8443 + udp/3479 | 443 + udp | WebRTC data channel; set up over HTTPS |
| **ICMP** | | | |
| `icmp` | — | — | ICMP / ICMPv6 echo (ping) requests, data in the payload |

The defaults are unprivileged ports, so a server can run without root.
`transfermapexec methods` prints the list.

**Shared listeners.** Methods given the same port share one listener where the
real thing would: `https`, `doh`, `grpc`, `ws` and `webrtc` signaling on one
HTTPS server; the `http-*` methods on the `http` server; `sftp` on the `ssh`
server; `turn` on the `stun` port. With standard ports, all five web methods
run on 443, as they would on a real host.

## Requirements

- Go 1.26+ to build (`go.mod` sets the minimum).
- No runtime dependencies: the compiled binary is self-contained.

## Build

### Build for the current machine

```bash
make native        # produces ./transfermapexec
# or:
go build -o transfermapexec .
```

### Build for all target platforms at once

```bash
make build         # outputs to ./dist/
```

### Build for a specific platform

Each command below is self-contained; run it from the project root.
`CGO_ENABLED=0` keeps the binary a pure-Go static build; `-trimpath` and
`-ldflags "-s -w"` keep it reproducible and small.

**Linux (x86-64):**
```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-linux-amd64 .
```

**Linux (arm64):**
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-linux-arm64 .
```

**Windows (x86-64):**
```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-windows-amd64.exe .
```

**macOS (Apple Silicon / arm64):**
```bash
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-darwin-arm64 .
```

**macOS (Intel / amd64):**
```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-darwin-amd64 .
```

> On Windows PowerShell, set the variables first, e.g.:
> ```powershell
> $env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
> go build -trimpath -ldflags "-s -w" -o dist/transfermapexec-windows-amd64.exe .
> ```

### Releases

`.github/workflows/release.yml` builds every platform and attaches the
binaries, with a `SHA256SUMS` file, to a GitHub Release whenever a version tag
is pushed:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow uses the same `make build` as a local build, with the newest
stable Go and its actions pinned to commit SHAs.

## Quick start

On the server (as root on Linux if you want `icmp`, or standard ports):

```bash
transfermapexec server -out ./received
```

On the client:

```bash
transfermapexec client -host 192.168.1.50 -all -file ./report.pdf
```

```
sending file "report.pdf" (58.6 KiB, sha256 84f38a08eb3b…) with 32 method(s) to 192.168.1.50 (IPv4)

  ok    tcp         v4  tcp/9001          1ms  55.3 MiB/s
  ok    https       v4  tcp/8443          1ms  44.7 MiB/s  HTTP/2.0
  ok    doh         v4  tcp/8443         19ms   3.0 MiB/s  HTTP/2.0, 429 chunks of 140 B, 431 packets sent, 0 resent
  FAIL  smb         v4  tcp/10445        5.0s              no answer on tcp/10445 within 5s (-connect-timeout): dropped by a firewall, ...
  ok    webrtc      v4  tcp/8443+udp    212ms 275.6 KiB/s  ICE udp 192.168.1.20:60503 -> 192.168.1.50:3479
  ...

worked (31/32): tcp tls http http-query ...
failed (1/32): smb
```

## IPv4 and IPv6

`-host` takes a name, an address, or several comma-separated:

```bash
transfermapexec client -host testserver -all -file x          # every family the name resolves to
transfermapexec client -host 192.168.1.50,fd00::50 -all -file x   # both, by address
transfermapexec client -host testserver -ip 4 -all -file x    # IPv4 only
```

Every method runs once per address (`v4` / `v6` in the results), and the
summary is per address. `-ip both` (the default) tests every family the
server has an address for, so IPv6 gets tested whenever there is an IPv6 path,
and costs nothing when there isn't. `-ip 4` or `-ip 6` restricts it. When a
family is not being tested, the client says so and how to add it.

Over IPv6, `icmp` uses ICMPv6 echo, `webrtc` uses only IPv6 ICE candidates, and
`turn` asks for an IPv6 peer, so each test really is IPv6 end to end.
Firewalls often have IPv4-only rules, which makes IPv6 the classic blind spot.

The server listens on both families by default (`-bind` picks one address).

## Server

```
transfermapexec server [flags]

  -methods string        methods to serve, comma-separated, or "all" (default "all")
  -bind string           IP address to listen on (default: all interfaces, IPv4 and IPv6)
  -ports string          per-method port overrides, e.g. "http=80,https=443,dns=53"
  -out string            directory to write received files into (default "received")
  -overwrite             replace an existing file of the same name (default true);
                         -overwrite=false adds a numeric suffix instead (report.1.pdf)
  -per-method            store each method's copy under OUT/<method>/
  -log string            path to the server log file (default "transfermapexec-server.log")
  -dns-domain string     domain the DNS methods' queries arrive under (default "mt.test")
  -ftp-pasv-port int     fixed port for FTP passive data connections (default: any free port)
  -webrtc-port int       UDP port for WebRTC media (default 3479)
  -webrtc-ip string      address(es) to advertise to WebRTC clients when behind NAT
  -v                     verbose logging (per-connection detail)
```

- **Files** are written to a temporary file, checked against their SHA-256,
  then renamed into place. A transfer that fails or arrives corrupted never
  replaces a good copy. By default each method overwrites the same file, so
  after `-all` you have one copy; `-per-method` keeps one per method.
- Incoming names are reduced to a safe base name, so a client cannot write
  outside `-out`.
- **Text** is printed to stdout and the log file, tagged with the method.
- At startup the server checks each TCP port for another program already
  accepting connections on it. macOS and BSD let two programs share a port
  that way, and the other one silently takes the connections. Docker Desktop,
  Lima/Colima and SSH port forwards often hold ports like 8080 and 8443.
- A transfer that moves no data for 30 seconds is dropped. `Ctrl-C` or
  `SIGTERM` stops the server.

## Client

```
transfermapexec client -host HOST (-method LIST | -all) (-file PATH | -text STRING) [flags]

  -host string             server name or IP, or several comma-separated (required)
  -ip string               address families: "both" (default), "4" or "6"
  -method string           method(s) to use, comma-separated
  -all                     try every method, one after another, and report which worked
  -file / -text            what to send (exactly one)
  -name string             override the filename/label stored with the payload
  -port int                port to use (only with a single -method)
  -ports string            per-method port overrides (must match the server's)
  -connect-timeout dur     how long a method may take to reach the server before
                           it counts as blocked (default 5s)
  -idle-timeout dur        abandon a transfer that makes no progress for this long (default 15s)
  -timeout dur             hard limit on each method, start to finish (default 5m)
  -parallel                run the methods at the same time
  -sni string              TLS server name (default: -host when it is a name)
  -dns-domain string       domain for DNS queries (default "mt.test"; must match the server)
  -dns-server host:port    send the dns method's queries through this resolver
  -json                    print the results as JSON
  -report PATH             also write a self-contained HTML report to PATH
  -v                       verbose logging
```

The exit status is 0 if every method worked, 1 if any failed, and 2 for
bad arguments.

### HTML report

`-report` writes a standalone HTML page of the run alongside the usual output:

```bash
transfermapexec client -host 192.168.1.50 -all -file ./report.pdf -report run.html
```

The page needs no network or external files — open it in any browser. It shows
the payload (name, size, SHA-256), totals, and, per address family, a table of
every method with its status, endpoint, time, rate and the same detail or
failure reason the terminal prints, with buttons to filter down to just what
worked or just what failed. It works with `-json` too.

### Timeouts

Every method uses the same three timeouts:

| Timeout | Default | What it catches |
|---|---|---|
| `-connect-timeout` | 5s | The method never reaches the server: no TCP connect, TLS/SSH/QUIC/SMB handshake, WebRTC connection, or first reply over UDP, DNS or ICMP. This is what a firewall that silently drops packets looks like. |
| `-idle-timeout` | 15s | The transfer started, then stopped moving: a middlebox that lets the handshake through but holds the data. |
| `-timeout` | 5m | Hard cap per method, however slowly it is still moving. Raise it for large files over the DNS methods. |

A port that actively refuses (TCP RST, ICMP "port unreachable", or the
client's own firewall) fails immediately. With everything blocked, `-all`
takes about methods × families × `-connect-timeout`; with `-parallel` it takes
one timeout.

### Reading the failures

The client says what a failure most likely means:

| Message | Meaning |
|---|---|
| `connection refused on tcp/443` | Something actively rejected it: nothing listening, or a firewall sending RSTs. |
| `no answer on udp/4433 within 5s` | Packets vanish: a firewall dropping them, or no server. |
| `this machine refused to send to udp/123 (operation not permitted)` | The **client's own** firewall blocks it. |
| `connected, but the handshake got no answer` | Something on the path accepted the connection but holds it. |
| `something other than a transfermapexec server answered on tcp/443 (403 ..., Server: "...")` | A proxy's block page, or another program on the port. Every web response from the server carries an `X-Transfermapexec` header, so these are never counted as success. |
| `signaling over tcp/443 worked, but the WebRTC connection (ICE/DTLS over udp/3479) did not come up` | HTTPS is allowed, but the call's UDP media is blocked. |
| `DNS answered Refused: the queries are not reaching the transfermapexec server` | A resolver isn't forwarding the test domain. |
| `server refused the transfer: SHA-256 mismatch` | The data got through but changed on the way. |
| `server refused the transfer: <reason>` | The server got the data but could not store it (it says why). |

### Standard ports

To test what a firewall does with the well-known ports, run the server as root
and give both sides the same overrides:

```bash
P="http=80,http-query=80,http-cookie=80,http-header=80,https=443,doh=443,grpc=443,ws=443,webrtc=443,http3=443,ssh=22,sftp=22,smtp=25,ftp=21,smb=445,dot=853,dns=53,dns-tcp=53,tftp=69,ntp=123,syslog=514,snmp=162,mqtt=1883,irc=6667,xmpp=5222,stun=3478,turn=3478"
sudo transfermapexec server -ports "$P"
transfermapexec client -host testserver -all -ports "$P" -file ./report.pdf
```

`quic` stays on 4433/udp (443/udp is `http3`). On Windows and macOS, port 445
belongs to the OS's own file sharing, so use a Linux server for `smb=445`.

## Method notes

**udp, dns, dns-tcp, dot, doh, http-query/cookie/header, ntp, syslog, snmp,
stun, turn, icmp** carry the data through a small reliability layer of their
own. The frame is split into chunks, each wrapped in that protocol's message
(a query name, a cookie, an NTP extension field, a ping payload, ...), and sent
with a sliding window. The server acknowledges each one in the protocol's
reply, and anything unacknowledged is resent with a timeout that adapts to the
round-trip time. Tested with 10% packet loss plus jitter: all complete.

**Web, without a body.** `http-query`, `http-cookie` and `http-header` send many
small GETs (`/search?q=…`, `Cookie: session=…`, `Authorization: Bearer …`),
about 1.4–3 KB of data each, several at a time over keep-alive connections, as
a browser would. Inspection that only looks at request bodies sees nothing.

**DNS tunnelling** sends TXT queries for names like
`<base32>.<base32>.<base32>.<base32>.mt.test`, about 140 bytes of data each; the
answer is a TXT record. `dns` goes over UDP, straight to the server, or with
`-dns-server` through a resolver that forwards the domain to it (a delegation,
or e.g. dnsmasq's `--server=/mt.test/192.168.1.50#5300`). `dns-tcp` and `dot`
pipeline the queries on one connection; `doh` POSTs them over HTTP/2, as
browsers do. The encoding survives resolvers that randomise letter case. The
server answers other names in its domain with an empty answer (not NXDOMAIN,
so resolvers using QNAME minimisation keep going) and refuses names outside
it, so it is not an open resolver.

**smb** connects with NTLMv2 (user and password `transfermapexec`), mounts the
share `\\server\upload`, and writes the file, as `copy report.pdf
\\server\upload\` would. The server is a real SMB2/3 server
(macos-fuse-t/go-smb2) with an in-memory share. SMB's close response cannot
carry the verdict, so the client then reads it back from
`report.pdf.mtresult` on the same share.

**grpc** is a client-streaming call to `/transfermapexec.v1.Transfer/Upload`, with
`Chunk { bytes data = 1; }` messages. It is real gRPC on the wire (HTTP/2,
`application/grpc`, `te: trailers`, length-prefixed protobuf, `grpc-status`
trailer), implemented on Go's HTTP/2 stack rather than grpc-go.

**mqtt** behaves like an IoT device: CONNECT, SUBSCRIBE to
`transfermapexec/<id>/result`, PUBLISH 32 KB chunks at QoS 1 to
`transfermapexec/<id>/upload`. The server, acting as the broker, publishes the
verdict to the result topic.

**irc** registers (NICK/USER), joins `#transfermapexec` and posts the data base64
encoded as PRIVMSG lines. The server answers with a NOTICE.

**xmpp** opens a stream, upgrades with STARTTLS (required, as on real
servers), authenticates with SASL ANONYMOUS, binds a resource, and sends the
data as an In-Band Bytestream (XEP-0047): `<open/>`, 4 KB `<data/>` blocks,
`<close/>`.

**ntp** sends real NTPv4 client requests, and the server answers with real
server responses (timestamps included). The data rides in an RFC 7822
extension field. **syslog** sends RFC 5424 messages (`local0.info`). Real
syslog is one-way, so the acknowledgements come back as syslog messages to the
client's port: a firewall that lets syslog out but not those replies back
makes the method fail even if data arrived. **snmp** sends SNMPv2c
InformRequests (the acknowledged form of a trap) under net-snmp's experimental
OID subtree; the Response carries the acknowledgement.

**stun** puts the data in a comprehension-optional attribute of Binding
requests, which real STUN servers ignore; the success response carries the
reply. **turn** goes through what a call relay sees: Allocate, 401 with a
nonce, Allocate with long-term credentials and MESSAGE-INTEGRITY,
CreatePermission, ChannelBind, then ChannelData both ways, and a Refresh with
lifetime 0 at the end. The server is both relay and peer.

**webrtc** is a browser-style WebRTC session (pion/webrtc). The client POSTs
its SDP offer to `/webrtc/offer` on the HTTPS port and gets an answer. That is
the signaling, which real apps also do over HTTPS. Then it connects with ICE,
DTLS and SCTP over UDP to the server's `-webrtc-port`, and sends the data on a
reliable data channel. No STUN/TURN servers are used: client and server reach
each other directly. Behind NAT, give the server `-webrtc-ip <public address>`.

**icmp / ICMPv6** sends echo requests carrying the data; the server answers
with its own echo replies. The server's kernel also answers every ping; the
client ignores those, so a host that answers pings is not mistaken for a
working transfer.
- *Server*: Linux, as root or with `CAP_NET_RAW`
  (`sudo setcap cap_net_raw+ep ./transfermapexec`). macOS and the BSDs answer
  pings in the kernel and never pass them to a program.
- *Client*: no root needed on macOS, or on Linux when
  `net.ipv4.ping_group_range` includes the user (the default on most current
  distributions and in Docker). Otherwise root; admin on Windows.

**tftp** answers each transfer from a new port, as TFTP does. Stateful
firewalls and NAT often break that, so it is worth testing on its own. **ftp**
uses passive mode, so each upload opens a second connection to a data port;
use `-ftp-pasv-port` to pin it. **ssh/sftp** accept any client without
authentication and generate a host key at each start.

**TLS** (tls, https, ws, grpc, doh, dot, quic, http3, xmpp): the server
generates a self-signed certificate in memory at each start, and the client
skips verification. TLS 1.3 only. The ClientHello carries `-sni`, or the
`-host` name.

## What was tested

- **Linux server and client, IPv4 and IPv6** (Docker, IPv6 network, server as
  root on the standard ports above, client as a normal user): **64 of 64**
  transfers worked (32 methods × 2 families). `-host` given as a name found
  both families.
- **10% packet loss with jitter** (netem): 64 of 64, in about 20 seconds for a
  60 KB file.
- **Protocol identification** (Wireshark/tshark 4.6 on the capture): each port
  dissects as its protocol, including SMB2 with GSS-API/SPNEGO/NTLMSSP, SMTP
  with IMF, MQTT, IRC, XMPP then TLS, DNS on 53/tcp and 53/udp, NTP, SNMP,
  syslog, STUN (valid FINGERPRINT on every message), DTLS+STUN for WebRTC,
  QUIC, TLS. No malformed packets.
- **An egress firewall** (iptables on the client: tcp/445 dropped, tcp/443
  rejected, all UDP but 53 dropped, IPv6 pings dropped): the 443 methods failed
  at once as refused, smb after the connect timeout, every UDP method at once
  as blocked locally; DNS tunnelling, HTTP and the rest got through, and ICMP
  worked over IPv4 but not IPv6. The whole run took 7 seconds.
- **Refusals**: with the server unable to store files, all 31 methods that
  reached it reported the server's reason.

## Wire format

Every method carries the same frame, inside whatever it wraps it in:

```
[4  bytes] magic            "MTX1"
[1  byte ] type             0x01 = file, 0x02 = text
[2  bytes] name length      big-endian uint16
[N  bytes] name             filename (file) or optional label (text), UTF-8
[8  bytes] payload length   big-endian uint64
[32 bytes] SHA-256          of the payload
[M  bytes] payload          raw file bytes or UTF-8 text
```

The verdict comes back in whatever form the method allows:

| Methods | Verdict |
|---|---|
| tcp, tls, quic | a status line, `OK` or `ERR <reason>` |
| http, https, http3 | the HTTP status |
| ws | the close code |
| grpc | the `grpc-status` trailer |
| ssh / sftp | the exit status / the status of closing the file |
| smtp, ftp | the reply code after the data |
| tftp | the ACK of the last block, or an ERROR |
| smb | the `<name>.mtresult` file on the share |
| mqtt, irc, xmpp, webrtc | a message back in the protocol: result topic, NOTICE, IBB close result, data channel message |
| datagram methods (udp, DNS ×4, http-*, ntp, syslog, snmp, stun, turn, icmp) | the acknowledgement of the final message |

## Project layout

```
main.go       subcommand dispatch
methods.go    method registry, default ports, shared listeners, -ports parsing
client.go     "client": targets and address families, timeouts, results
server.go     "server": starts the listeners; stores and verifies what arrives
frame.go      the frame format
netutil.go    shared helpers: idle guard, adaptive resend timeout, verdicts
tlsconf.go    self-signed certificate, client/server TLS configs
dgram.go      reliable chunked transfer for message-based methods
m_stream.go   tcp, tls, quic
m_http.go     the web listener: http, https, http3, ws (and routing for the rest)
m_httpget.go  http-query, http-cookie, http-header
m_grpc.go     grpc
m_webrtc.go   webrtc
m_dns.go      dns, dns-tcp, dot, doh
m_dgram.go    udp, icmp, and the codec plumbing for UDP protocols
m_monitor.go  ntp, syslog, snmp
m_stun.go     stun, turn
m_ssh.go      ssh, sftp
m_smb.go      smb
m_smtp.go     smtp
m_ftp.go      ftp
m_tftp.go     tftp
m_mqtt.go     mqtt
m_irc.go      irc
m_xmpp.go     xmpp
```

To add a method, write a `send` and a `serve` function and add an entry to
`methods.go`. For a message-based protocol, a `dgCodec` (wrap and unwrap) is
usually all it takes; the server's `receive` does the storing and checking for
every method.

Libraries: quic-go (QUIC, HTTP/3), coder/websocket, x/crypto/ssh, pkg/sftp,
x/net (DNS messages, ICMP), pion/webrtc, hirochachacha/go-smb2 (SMB client),
macos-fuse-t/go-smb2 (SMB server). Everything else is written here on the
standard library.
