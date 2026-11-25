package main

// STUN and TURN (RFC 8489, RFC 8656), the protocols video calls use to find
// their public address and to relay media when a direct path is blocked.
// Both share one UDP port on the server, as on a real TURN server.
//
// stun: each message rides in a Binding request, in a comprehension-optional
// attribute that real STUN servers ignore; the Binding success response
// (with the usual XOR-MAPPED-ADDRESS) carries the reply.
//
// turn: the client goes through the real sequence: Allocate, answered with
// 401 and a nonce; Allocate again with long-term credentials and
// MESSAGE-INTEGRITY; CreatePermission and ChannelBind for a peer; then
// ChannelData messages both ways, as relayed media flows; finally a Refresh
// with lifetime 0 to free the allocation. The server is both relay and peer:
// what the client sends to the peer is what the server receives.

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	stunMagic = 0x2112A442

	stunBinding          = 0x0001
	turnAllocate         = 0x0003
	turnRefresh          = 0x0004
	turnSendIndication   = 0x0016
	turnDataIndication   = 0x0017
	turnCreatePermission = 0x0008
	turnChannelBind      = 0x0009

	stunClassSuccess = 0x0100
	stunClassError   = 0x0110

	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrChannelNumber      = 0x000C
	attrLifetime           = 0x000D
	attrXorPeerAddress     = 0x0012
	attrData               = 0x0013
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrXorRelayedAddress  = 0x0016
	attrRequestedTransport = 0x0019
	attrXorMappedAddress   = 0x0020
	attrSoftware           = 0x8022
	attrFingerprint        = 0x8028
	attrMTData             = 0xC0DE // comprehension-optional (private range)

	turnUser     = appName
	turnPassword = appName
	turnRealm    = appName
	turnChannel  = 0x4000
)

type stunAttr struct {
	typ uint16
	val []byte
}

type stunMsg struct {
	typ   uint16
	tid   [12]byte
	attrs []stunAttr
}

func newStun(typ uint16) *stunMsg {
	m := &stunMsg{typ: typ}
	for i := 0; i < 12; i += 4 {
		binary.BigEndian.PutUint32(m.tid[i:], randUint32())
	}
	return m
}

// respond starts a response of the given class to m.
func (m *stunMsg) respond(class uint16) *stunMsg {
	return &stunMsg{typ: m.typ&^0x0110 | class, tid: m.tid}
}

func (m *stunMsg) add(typ uint16, val []byte) *stunMsg {
	m.attrs = append(m.attrs, stunAttr{typ, val})
	return m
}

func (m *stunMsg) get(typ uint16) []byte {
	for _, a := range m.attrs {
		if a.typ == typ {
			return a.val
		}
	}
	return nil
}

func (m *stunMsg) class() uint16 { return m.typ & 0x0110 }

func (m *stunMsg) errorCode() (int, string) {
	v := m.get(attrErrorCode)
	if len(v) < 4 {
		return 0, ""
	}
	return int(v[2]&7)*100 + int(v[3]), string(v[4:])
}

// encode serializes m, adding MESSAGE-INTEGRITY (when key is set) and
// FINGERPRINT, each computed over the message up to it with the length
// field already counting it.
func (m *stunMsg) encode(key []byte) []byte {
	var body []byte
	for _, a := range m.attrs {
		body = binary.BigEndian.AppendUint16(body, a.typ)
		body = binary.BigEndian.AppendUint16(body, uint16(len(a.val)))
		body = append(body, a.val...)
		body = append(body, make([]byte, (4-len(a.val)%4)%4)...)
	}
	out := binary.BigEndian.AppendUint16(nil, m.typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	out = binary.BigEndian.AppendUint32(out, stunMagic)
	out = append(out, m.tid[:]...)
	out = append(out, body...)
	if key != nil {
		binary.BigEndian.PutUint16(out[2:], uint16(len(out)-20+24))
		mac := hmac.New(sha1.New, key)
		mac.Write(out)
		out = binary.BigEndian.AppendUint16(out, attrMessageIntegrity)
		out = binary.BigEndian.AppendUint16(out, 20)
		out = append(out, mac.Sum(nil)...)
	}
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)-20+8))
	crc := crc32.ChecksumIEEE(out) ^ 0x5354554e
	out = binary.BigEndian.AppendUint16(out, attrFingerprint)
	out = binary.BigEndian.AppendUint16(out, 4)
	return binary.BigEndian.AppendUint32(out, crc)
}

func isStun(b []byte) bool {
	return len(b) >= 20 && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:]) == stunMagic
}

func parseStun(b []byte) (*stunMsg, error) {
	if !isStun(b) {
		return nil, errors.New("not STUN")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n%4 != 0 || 20+n > len(b) {
		return nil, errors.New("bad STUN length")
	}
	m := &stunMsg{typ: binary.BigEndian.Uint16(b)}
	copy(m.tid[:], b[8:20])
	for p := b[20 : 20+n]; len(p) >= 4; {
		typ, l := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if 4+l > len(p) {
			return nil, errors.New("bad STUN attribute")
		}
		m.attrs = append(m.attrs, stunAttr{typ, p[4 : 4+l]})
		p = p[min(len(p), 4+(l+3)&^3):]
	}
	return m, nil
}

// stunIntegrityOK checks the MESSAGE-INTEGRITY of the raw message b.
func stunIntegrityOK(b, key []byte) bool {
	for off := 20; off+4 <= len(b); {
		typ, l := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+2:]))
		if typ == attrMessageIntegrity {
			if l != 20 || off+24 > len(b) {
				return false
			}
			head := append([]byte(nil), b[:off]...)
			binary.BigEndian.PutUint16(head[2:], uint16(off-20+24))
			mac := hmac.New(sha1.New, key)
			mac.Write(head)
			return hmac.Equal(mac.Sum(nil), b[off+4:off+24])
		}
		off += 4 + (l+3)&^3
	}
	return false
}

func turnKey(user, realm, password string) []byte {
	sum := md5.Sum([]byte(user + ":" + realm + ":" + password))
	return sum[:]
}

// xorAddr encodes an XOR-*-ADDRESS attribute value.
func xorAddr(ip net.IP, port int, tid [12]byte) []byte {
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[:], stunMagic)
	copy(mask[4:], tid[:])
	b := []byte{0, 1}
	raw := ip.To4()
	if raw == nil {
		b[1], raw = 2, ip.To16()
	}
	b = binary.BigEndian.AppendUint16(b, uint16(port)^uint16(stunMagic>>16))
	for i, c := range raw {
		b = append(b, c^mask[i])
	}
	return b
}

func parseXorAddr(v []byte, tid [12]byte) (net.IP, int, error) {
	if len(v) != 8 && len(v) != 20 {
		return nil, 0, errors.New("bad address attribute")
	}
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[:], stunMagic)
	copy(mask[4:], tid[:])
	ip := make(net.IP, len(v)-4)
	for i := range ip {
		ip[i] = v[4+i] ^ mask[i]
	}
	return ip, int(binary.BigEndian.Uint16(v[2:]) ^ uint16(stunMagic>>16)), nil
}

func channelData(ch uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, ch)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// ---- stun client ----------------------------------------------------------

type stunTransport struct{ c net.Conn }

func (t *stunTransport) close() error { return t.c.Close() }

func (t *stunTransport) send(msg []byte) error {
	m := newStun(stunBinding).add(attrSoftware, []byte(appName)).add(attrMTData, msg)
	_, err := t.c.Write(m.encode(nil))
	return err
}

func (t *stunTransport) recv() ([]byte, error) {
	buf := make([]byte, 65535)
	for {
		n, err := t.c.Read(buf)
		if err != nil {
			return nil, err
		}
		if m, err := parseStun(buf[:n]); err == nil && m.typ == stunBinding|stunClassSuccess {
			if v := m.get(attrMTData); v != nil {
				return v, nil
			}
		}
	}
}

func sendSTUN(a *attempt) (string, error) {
	c, err := a.dial("udp")
	if err != nil {
		return "", err
	}
	return a.sendDatagrams(&stunTransport{c}, dgParams{chunk: 1000, window: 32, rto: 300 * time.Millisecond})
}

// ---- turn client ----------------------------------------------------------

type turnClient struct {
	a            *attempt
	c            net.Conn
	key          []byte
	realm, nonce []byte
	peerIP       net.IP
	peerPort     int
	relay        string
}

// roundTrip sends req (signed once credentials are known) until a response
// with its transaction ID arrives, or limit passes.
func (t *turnClient) roundTrip(req *stunMsg, limit time.Duration) (*stunMsg, error) {
	if t.key != nil {
		req.add(attrUsername, []byte(turnUser)).add(attrRealm, t.realm).add(attrNonce, t.nonce)
	}
	pkt := req.encode(t.key)
	deadline := time.Now().Add(limit)
	buf := make([]byte, 65535)
	for rto := 250 * time.Millisecond; ; rto = min(2*rto, 2*time.Second) {
		if _, err := t.c.Write(pkt); err != nil {
			return nil, err
		}
		wait := time.Now().Add(rto)
		if wait.After(deadline) {
			wait = deadline
		}
		_ = t.c.SetReadDeadline(wait)
		for {
			n, err := t.c.Read(buf)
			if err != nil {
				if isTimeout(err) && time.Now().Before(deadline) && t.a.ctx.Err() == nil {
					break // resend
				}
				_ = t.c.SetReadDeadline(time.Time{})
				return nil, err
			}
			if m, err := parseStun(buf[:n]); err == nil && m.tid == req.tid {
				_ = t.c.SetReadDeadline(time.Time{})
				return m, nil
			}
		}
	}
}

// request runs one authenticated request built by build, retrying once
// with a fresh nonce if the server says the old one went stale.
func (t *turnClient) request(typ uint16, build func(req *stunMsg)) (*stunMsg, error) {
	for try := 0; ; try++ {
		req := newStun(typ)
		build(req)
		resp, err := t.roundTrip(req, t.a.opts.idleTimeout)
		if err != nil {
			return nil, err
		}
		if resp.class() == stunClassSuccess {
			return resp, nil
		}
		code, reason := resp.errorCode()
		if code == 438 && try == 0 { // stale nonce
			t.nonce = resp.get(attrNonce)
			continue
		}
		return nil, &refusedError{fmt.Sprintf("TURN error %d %s", code, reason)}
	}
}

func sendTURN(a *attempt) (string, error) {
	c, err := a.dial("udp")
	if err != nil {
		return "", err
	}
	t := &turnClient{a: a, c: c, peerIP: a.tgt.ip, peerPort: 9}
	stop := closeOnDone(a, c)
	defer stop()
	fail := func(step string, err error) (string, error) {
		c.Close()
		return "", fmt.Errorf("%s: %w", step, err)
	}

	// Allocate without credentials: the server answers 401 with a realm and
	// nonce, as real TURN servers do; this answer is the first contact.
	transport := []byte{17, 0, 0, 0} // UDP
	resp, err := t.roundTrip(newStun(turnAllocate).add(attrRequestedTransport, transport).add(attrSoftware, []byte(appName)), a.opts.connectTimeout)
	if err != nil {
		c.Close()
		return "", a.unreachable(err)
	}
	a.connected.Store(true)
	a.guard.touch()
	if resp.class() == stunClassError {
		if code, reason := resp.errorCode(); code != 401 {
			return fail("allocate", &refusedError{fmt.Sprintf("TURN error %d %s", code, reason)})
		}
		t.realm, t.nonce = resp.get(attrRealm), resp.get(attrNonce)
		t.key = turnKey(turnUser, string(t.realm), turnPassword)
		resp, err = t.request(turnAllocate, func(r *stunMsg) {
			r.add(attrRequestedTransport, transport).add(attrLifetime, binary.BigEndian.AppendUint32(nil, 600))
		})
		if err != nil {
			return fail("allocate", err)
		}
	}
	if ip, port, err := parseXorAddr(resp.get(attrXorRelayedAddress), resp.tid); err == nil {
		t.relay = net.JoinHostPort(ip.String(), fmt.Sprint(port))
	}

	// A permission and a channel for the peer (the server itself).
	if _, err := t.request(turnCreatePermission, func(r *stunMsg) {
		r.add(attrXorPeerAddress, xorAddr(t.peerIP, t.peerPort, r.tid))
	}); err != nil {
		return fail("create permission", err)
	}
	if _, err := t.request(turnChannelBind, func(r *stunMsg) {
		r.add(attrChannelNumber, []byte{turnChannel >> 8, turnChannel & 0xff, 0, 0})
		r.add(attrXorPeerAddress, xorAddr(t.peerIP, t.peerPort, r.tid))
	}); err != nil {
		return fail("channel bind", err)
	}

	detail, err := a.sendDatagrams(&turnTransport{t}, dgParams{chunk: 1100, window: 32, rto: 300 * time.Millisecond})
	if t.relay != "" {
		detail = "relay " + t.relay + ", " + detail
	}
	return detail, err
}

// turnTransport carries the datagram protocol in ChannelData messages on
// the bound channel.
type turnTransport struct{ t *turnClient }

func (tt *turnTransport) send(msg []byte) error {
	_, err := tt.t.c.Write(channelData(turnChannel, msg))
	return err
}

func (tt *turnTransport) recv() ([]byte, error) {
	buf := make([]byte, 65535)
	for {
		n, err := tt.t.c.Read(buf)
		if err != nil {
			return nil, err
		}
		b := buf[:n]
		if n >= 4 && b[0]&0xC0 == 0x40 && binary.BigEndian.Uint16(b) == turnChannel {
			l := int(binary.BigEndian.Uint16(b[2:]))
			if 4+l <= n {
				return b[4 : 4+l], nil
			}
		}
		if m, err := parseStun(b); err == nil && m.typ == turnDataIndication {
			if v := m.get(attrData); v != nil {
				return v, nil
			}
		}
	}
}

// close frees the allocation (Refresh with lifetime 0), then the socket.
func (tt *turnTransport) close() error {
	t := tt.t
	if t.key != nil {
		req := newStun(turnRefresh).add(attrLifetime, []byte{0, 0, 0, 0})
		req.add(attrUsername, []byte(turnUser)).add(attrRealm, t.realm).add(attrNonce, t.nonce)
		_, _ = t.c.Write(req.encode(t.key))
	}
	return t.c.Close()
}

// ---- server ---------------------------------------------------------------

type turnAlloc struct {
	nonce    []byte
	active   bool
	relay    *net.UDPAddr
	channels map[uint16]bool
	last     time.Time
}

type stunServer struct {
	s      *Server
	on     methodSet
	pc     net.PacketConn
	stunDG *dgServer
	turnDG *dgServer
	key    []byte

	mu        sync.Mutex
	allocs    map[string]*turnAlloc
	nextRelay int
}

func serveSTUN(s *Server, addr string, on methodSet) (io.Closer, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	ss := &stunServer{s: s, on: on, pc: pc, key: turnKey(turnUser, turnRealm, turnPassword),
		allocs: map[string]*turnAlloc{}, nextRelay: 49152}
	if on["stun"] {
		ss.stunDG = newDgServer(s, "stun")
	}
	if on["turn"] {
		ss.turnDG = newDgServer(s, "turn")
	}
	go ss.loop()
	return closerFunc(func() error {
		if ss.stunDG != nil {
			ss.stunDG.close()
		}
		if ss.turnDG != nil {
			ss.turnDG.close()
		}
		return pc.Close()
	}), nil
}

func (ss *stunServer) loop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := ss.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if out := ss.handle(buf[:n], from); out != nil {
			_, _ = ss.pc.WriteTo(out, from)
		}
	}
}

func (ss *stunServer) handle(b []byte, from net.Addr) []byte {
	ua, _ := from.(*net.UDPAddr)
	key := from.String()

	// ChannelData: media from the client to the peer, which is us.
	if len(b) >= 4 && b[0]&0xC0 == 0x40 {
		if ss.turnDG == nil {
			return nil
		}
		ch, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		ss.mu.Lock()
		al := ss.allocs[key]
		ok := al != nil && al.channels[ch]
		if ok {
			al.last = time.Now()
		}
		ss.mu.Unlock()
		if !ok || 4+l > len(b) {
			return nil
		}
		if reply := ss.turnDG.handle(b[4:4+l], key); reply != nil {
			return channelData(ch, reply)
		}
		return nil
	}

	req, err := parseStun(b)
	if err != nil || req.class() != 0 && req.typ != turnSendIndication {
		return nil
	}

	if req.typ == stunBinding {
		resp := req.respond(stunClassSuccess)
		if ua != nil {
			resp.add(attrXorMappedAddress, xorAddr(ua.IP, ua.Port, req.tid))
		}
		resp.add(attrSoftware, []byte(appName))
		if v := req.get(attrMTData); v != nil && ss.stunDG != nil {
			if reply := ss.stunDG.handle(v, key); reply != nil {
				resp.add(attrMTData, reply)
			}
		}
		return resp.encode(nil)
	}
	if ss.turnDG == nil || ua == nil {
		return nil
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()
	al := ss.allocs[key]

	// Everything but a Send indication must carry valid long-term
	// credentials; without them, the answer is 401 with a fresh nonce.
	if req.typ != turnSendIndication {
		if al == nil {
			if len(ss.allocs) > 1024 {
				ss.reap()
			}
			al = &turnAlloc{nonce: []byte(fmt.Sprintf("%08x%08x", randUint32(), randUint32())), channels: map[uint16]bool{}}
			ss.allocs[key] = al
		}
		al.last = time.Now()
		if req.get(attrMessageIntegrity) == nil || string(req.get(attrUsername)) != turnUser {
			return req.respond(stunClassError).
				add(attrErrorCode, []byte{0, 0, 4, 1, 'U', 'n', 'a', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'e', 'd'}).
				add(attrRealm, []byte(turnRealm)).add(attrNonce, al.nonce).encode(nil)
		}
		if !bytes.Equal(req.get(attrNonce), al.nonce) {
			return req.respond(stunClassError).
				add(attrErrorCode, []byte{0, 0, 4, 38, 'S', 't', 'a', 'l', 'e', ' ', 'N', 'o', 'n', 'c', 'e'}).
				add(attrRealm, []byte(turnRealm)).add(attrNonce, al.nonce).encode(nil)
		}
		if !stunIntegrityOK(b, ss.key) {
			return req.respond(stunClassError).
				add(attrErrorCode, []byte{0, 0, 4, 1, 'B', 'a', 'd', ' ', 'c', 'r', 'e', 'd', 'e', 'n', 't', 'i', 'a', 'l', 's'}).
				add(attrRealm, []byte(turnRealm)).add(attrNonce, al.nonce).encode(nil)
		}
	}

	switch req.typ {
	case turnAllocate:
		if !al.active {
			al.active = true
			al.relay = &net.UDPAddr{IP: localIPFor(ua), Port: ss.nextRelay}
			ss.nextRelay = 49152 + (ss.nextRelay-49152+1)%16384
			ss.s.debugf("turn", "allocation for %s: relay %s", key, al.relay)
		}
		return req.respond(stunClassSuccess).
			add(attrXorRelayedAddress, xorAddr(al.relay.IP, al.relay.Port, req.tid)).
			add(attrLifetime, binary.BigEndian.AppendUint32(nil, 600)).
			add(attrXorMappedAddress, xorAddr(ua.IP, ua.Port, req.tid)).
			add(attrSoftware, []byte(appName)).encode(ss.key)
	case turnRefresh:
		if lt := req.get(attrLifetime); len(lt) == 4 && binary.BigEndian.Uint32(lt) == 0 {
			delete(ss.allocs, key)
		}
		return req.respond(stunClassSuccess).add(attrLifetime, req.get(attrLifetime)).encode(ss.key)
	case turnCreatePermission:
		return req.respond(stunClassSuccess).encode(ss.key)
	case turnChannelBind:
		if v := req.get(attrChannelNumber); len(v) == 4 {
			al.channels[binary.BigEndian.Uint16(v)] = true
		}
		return req.respond(stunClassSuccess).encode(ss.key)
	case turnSendIndication:
		// Data for the peer without a channel; the reply goes back in a Data
		// indication. (Indications get no response of their own.)
		v := req.get(attrData)
		if al == nil || !al.active || v == nil {
			return nil
		}
		ss.mu.Unlock()
		reply := ss.turnDG.handle(v, key)
		ss.mu.Lock()
		if reply == nil {
			return nil
		}
		ind := newStun(turnDataIndication)
		if p := req.get(attrXorPeerAddress); p != nil {
			if ip, port, err := parseXorAddr(p, req.tid); err == nil {
				ind.add(attrXorPeerAddress, xorAddr(ip, port, ind.tid))
			}
		}
		return ind.add(attrData, reply).encode(nil)
	}
	return nil
}

// reap drops allocations idle for over ten minutes. Called with mu held.
func (ss *stunServer) reap() {
	for k, al := range ss.allocs {
		if time.Since(al.last) > 10*time.Minute {
			delete(ss.allocs, k)
		}
	}
}

// localIPFor is the server's address on the route to the client (no packet
// is sent).
func localIPFor(client *net.UDPAddr) net.IP {
	c, err := net.DialUDP("udp", nil, client)
	if err != nil {
		return net.IPv4zero
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if strings.Contains(ip.String(), ":") && client.IP.To4() != nil {
		return net.IPv4zero
	}
	return ip
}
