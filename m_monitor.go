package main

// Monitoring protocols that firewalls often let out: ntp, syslog and snmp.
// Each wraps the datagram protocol (dgram.go) in its own, real packets:
//
//	ntp     NTPv4 client requests (mode 3) and server responses (mode 4)
//	        with real timestamps, the data in an RFC 7822 extension field.
//	syslog  RFC 5424 messages; the data is the base64 MSG part.
//	snmp    SNMPv2c InformRequests (the acknowledged form of a trap) and
//	        their Responses; the data is an OCTET STRING varbind.
//
// Real syslog is one-way, so the server's acknowledgements go back to the
// client's port as syslog messages too. A firewall that lets syslog out but
// not those replies back makes the method fail, even if data arrived.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---- ntp ------------------------------------------------------------------

// ntpEFType is the extension field type the data travels in: an unassigned
// value (RFC 7822 fields are type, length, value, padding).
const ntpEFType = 0x6D74

type ntpCodec struct{}

func ntpTime(t time.Time) []byte {
	secs := uint64(t.Unix() + 2208988800) // NTP counts from 1900
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return binary.BigEndian.AppendUint64(nil, secs<<32|frac)
}

// ntpPacket builds a 48-byte NTPv4 header followed by an extension field
// carrying msg.
func ntpPacket(header, msg []byte) []byte {
	value := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	value = append(value, msg...)
	length := 4 + len(value)
	length = (length + 3) &^ 3
	length = max(length, 28) // RFC 7822: the last field is at least 28 bytes without a MAC
	b := append(header, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[48:], ntpEFType)
	binary.BigEndian.PutUint16(b[50:], uint16(length))
	b = append(b, value...)
	return append(b, make([]byte, length-4-len(value))...)
}

// ntpData returns the message in pkt's extension field, if pkt is mode.
func ntpData(pkt []byte, mode byte) []byte {
	if len(pkt) < 48+4 || pkt[0]&7 != mode {
		return nil
	}
	for off := 48; off+4 <= len(pkt); {
		typ := binary.BigEndian.Uint16(pkt[off:])
		length := int(binary.BigEndian.Uint16(pkt[off+2:]))
		if length < 16 || off+length > len(pkt) {
			return nil
		}
		if typ == ntpEFType && length >= 6 {
			n := int(binary.BigEndian.Uint16(pkt[off+4:]))
			if 6+n <= length {
				return pkt[off+6 : off+6+n]
			}
		}
		off += length
	}
	return nil
}

func (ntpCodec) wrapRequest(msg []byte) []byte {
	h := make([]byte, 48)
	h[0] = 0<<6 | 4<<3 | 3 // leap 0, version 4, mode 3 (client)
	h[2] = 6               // poll: 64 s
	h[3] = 0xE9            // precision: about a microsecond
	copy(h[40:], ntpTime(time.Now()))
	return ntpPacket(h, msg)
}

func (ntpCodec) unwrapRequest(pkt []byte) []byte { return ntpData(pkt, 3) }

func (ntpCodec) wrapReply(req, reply []byte) []byte {
	now := time.Now()
	h := make([]byte, 48)
	h[0] = 0<<6 | 4<<3 | 4 // leap 0, version 4, mode 4 (server)
	h[1] = 2               // stratum 2
	h[2] = req[2]
	h[3] = 0xE9
	binary.BigEndian.PutUint32(h[4:], 0x00000100) // root delay: 1/256 s
	binary.BigEndian.PutUint32(h[8:], 0x00000100) // root dispersion
	copy(h[12:], []byte{127, 127, 1, 0})          // reference ID: local clock
	copy(h[16:], ntpTime(now.Add(-time.Minute)))  // reference time
	copy(h[24:], req[40:48])                      // origin: the client's transmit time
	copy(h[32:], ntpTime(now))                    // receive
	copy(h[40:], ntpTime(now))                    // transmit
	return ntpPacket(h, reply)
}

func (ntpCodec) unwrapReply(pkt []byte) []byte { return ntpData(pkt, 4) }

func sendNTP(a *attempt) (string, error) {
	return a.sendDatagramsUDP(ntpCodec{}, dgParams{chunk: 1000, window: 32, rto: 300 * time.Millisecond})
}

func serveNTP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return serveDatagramsUDP(s, addr, "ntp", ntpCodec{})
}

// ---- syslog ---------------------------------------------------------------

// syslogCodec writes RFC 5424 messages:
//
//	<134>1 2026-11-25T19:07:43.123Z - transfermapexec 4242 MT - <base64>
//
// (facility local0, severity info). The server's replies use MSGID MTACK.
type syslogCodec struct{ pid string }

func syslogLine(msgID, pid string, data []byte) []byte {
	return []byte(fmt.Sprintf("<134>1 %s - %s %s %s - %s",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), appName, pid, msgID, base64.StdEncoding.EncodeToString(data)))
}

func syslogData(pkt []byte, msgID string) []byte {
	f := strings.SplitN(string(pkt), " ", 8)
	if len(f) != 8 || !strings.HasPrefix(f[0], "<") || f[5] != msgID {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(f[7]))
	if err != nil {
		return nil
	}
	return b
}

func (c syslogCodec) wrapRequest(msg []byte) []byte  { return syslogLine("MT", c.pid, msg) }
func (syslogCodec) unwrapRequest(pkt []byte) []byte  { return syslogData(pkt, "MT") }
func (syslogCodec) wrapReply(_, reply []byte) []byte { return syslogLine("MTACK", "-", reply) }
func (syslogCodec) unwrapReply(pkt []byte) []byte    { return syslogData(pkt, "MTACK") }

func sendSyslog(a *attempt) (string, error) {
	// 640 bytes encode to under 1 KB per message, the classic syslog limit.
	return a.sendDatagramsUDP(syslogCodec{pid: strconv.Itoa(os.Getpid())}, dgParams{chunk: 640, window: 32, rto: 300 * time.Millisecond})
}

func serveSyslog(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return serveDatagramsUDP(s, addr, "syslog", syslogCodec{})
}

// ---- snmp -----------------------------------------------------------------

var (
	oidSysUpTime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSnmpTrapOID = []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	// Under net-snmp's netSnmpPlaypen (1.3.6.1.4.1.8072.9999), the subtree
	// set aside for local experiments.
	oidTrap = []int{1, 3, 6, 1, 4, 1, 8072, 9999, 1}
	oidData = []int{1, 3, 6, 1, 4, 1, 8072, 9999, 2, 0}
)

const (
	snmpCommunity = "public"
	berInteger    = 0x02
	berOctets     = 0x04
	berOID        = 0x06
	berSequence   = 0x30
	berTimeTicks  = 0x43
	pduResponse   = 0xA2
	pduInform     = 0xA6
)

var processStart = time.Now()

func berTLV(tag byte, parts ...[]byte) []byte {
	content := bytes.Join(parts, nil)
	b := []byte{tag}
	switch n := len(content); {
	case n < 0x80:
		b = append(b, byte(n))
	case n < 0x100:
		b = append(b, 0x81, byte(n))
	default:
		b = append(b, 0x82, byte(n>>8), byte(n))
	}
	return append(b, content...)
}

func berInt(tag byte, v int64) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(v))
	for len(b) > 1 && ((b[0] == 0 && b[1]&0x80 == 0) || (b[0] == 0xff && b[1]&0x80 != 0)) {
		b = b[1:]
	}
	return berTLV(tag, b)
}

func berOIDValue(oid []int) []byte {
	b := []byte{byte(oid[0]*40 + oid[1])}
	for _, n := range oid[2:] {
		var enc []byte
		for {
			enc = append([]byte{byte(n & 0x7f)}, enc...)
			if n >>= 7; n == 0 {
				break
			}
		}
		for i := 0; i < len(enc)-1; i++ {
			enc[i] |= 0x80
		}
		b = append(b, enc...)
	}
	return berTLV(berOID, b)
}

// berNext splits the first TLV off b.
func berNext(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("short BER")
	}
	tag, n, off := b[0], int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 || len(b) < 2+k {
			return 0, nil, nil, errors.New("bad BER length")
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		off = 2 + k
	}
	if len(b) < off+n {
		return 0, nil, nil, errors.New("short BER")
	}
	return tag, b[off : off+n], b[off+n:], nil
}

func snmpVarbind(oid []int, value []byte) []byte {
	return berTLV(berSequence, berOIDValue(oid), value)
}

// snmpMessage builds an SNMPv2c message with the given PDU type.
func snmpMessage(pdu byte, reqID []byte, data []byte) []byte {
	ticks := int64(time.Since(processStart) / (10 * time.Millisecond))
	return berTLV(berSequence,
		berInt(berInteger, 1), // version: SNMPv2c
		berTLV(berOctets, []byte(snmpCommunity)),
		berTLV(pdu,
			reqID,
			berInt(berInteger, 0), // error-status
			berInt(berInteger, 0), // error-index
			berTLV(berSequence,
				snmpVarbind(oidSysUpTime, berInt(berTimeTicks, ticks&0xffffffff)),
				snmpVarbind(oidSnmpTrapOID, berOIDValue(oidTrap)),
				snmpVarbind(oidData, berTLV(berOctets, data)),
			),
		),
	)
}

// snmpParse returns the PDU type, the encoded request-id and the data
// varbind's value of an SNMPv2c message.
func snmpParse(pkt []byte) (pdu byte, reqID, data []byte, err error) {
	tag, msg, _, err := berNext(pkt)
	if err != nil || tag != berSequence {
		return 0, nil, nil, errors.New("not SNMP")
	}
	if _, _, msg, err = berNext(msg); err != nil { // version
		return 0, nil, nil, err
	}
	if _, _, msg, err = berNext(msg); err != nil { // community
		return 0, nil, nil, err
	}
	pdu, body, _, err := berNext(msg)
	if err != nil {
		return 0, nil, nil, err
	}
	rest := body
	if _, _, rest, err = berNext(rest); err != nil { // request-id
		return 0, nil, nil, err
	}
	reqID = body[:len(body)-len(rest)]
	for range 2 { // error-status, error-index
		if _, _, rest, err = berNext(rest); err != nil {
			return 0, nil, nil, err
		}
	}
	_, vbs, _, err := berNext(rest)
	if err != nil {
		return 0, nil, nil, err
	}
	want := berOIDValue(oidData)
	for len(vbs) > 0 {
		var vb []byte
		if _, vb, vbs, err = berNext(vbs); err != nil {
			return 0, nil, nil, err
		}
		_, _, value, err := berNext(vb)
		if err != nil {
			return 0, nil, nil, err
		}
		if bytes.Equal(vb[:len(vb)-len(value)], want) {
			if tag, v, _, err := berNext(value); err == nil && tag == berOctets {
				data = v
			}
		}
	}
	return pdu, reqID, data, nil
}

type snmpCodec struct{}

func (snmpCodec) wrapRequest(msg []byte) []byte {
	return snmpMessage(pduInform, berInt(berInteger, int64(randUint32()&0x7fffffff)), msg)
}

func (snmpCodec) unwrapRequest(pkt []byte) []byte {
	if pdu, _, data, err := snmpParse(pkt); err == nil && pdu == pduInform {
		return data
	}
	return nil
}

func (snmpCodec) wrapReply(req, reply []byte) []byte {
	_, reqID, _, _ := snmpParse(req)
	return snmpMessage(pduResponse, reqID, reply)
}

func (snmpCodec) unwrapReply(pkt []byte) []byte {
	if pdu, _, data, err := snmpParse(pkt); err == nil && pdu == pduResponse {
		return data
	}
	return nil
}

func sendSNMP(a *attempt) (string, error) {
	return a.sendDatagramsUDP(snmpCodec{}, dgParams{chunk: 1000, window: 32, rto: 300 * time.Millisecond})
}

func serveSNMP(s *Server, addr string, _ methodSet) (io.Closer, error) {
	return serveDatagramsUDP(s, addr, "snmp", snmpCodec{})
}
