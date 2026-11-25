package main

// The webrtc method is a browser-style WebRTC session (pion/webrtc): the
// client POSTs its SDP offer to /webrtc/offer on the server's HTTPS port (the
// signaling, which real apps also do over HTTPS), gets an answer, and then
// connects over UDP with ICE, DTLS and SCTP to the server's -webrtc-port. The
// frame goes over a reliable, ordered data channel; the server answers on the
// same channel with "OK" or "ERR <reason>", the verdict.
//
// No STUN or TURN servers are configured: the client and server reach each
// other directly, on host candidates.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
)

const (
	webrtcPath  = "/webrtc/offer"
	webrtcLabel = "transfermapexec"
	rtcMessage  = 16 << 10 // the message size every WebRTC stack accepts
	rtcBuffered = 1 << 20  // pause sending above this much unsent data
)

func quietPion() logging.LoggerFactory {
	return &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled}
}

func sendWebRTC(a *attempt) (string, error) {
	se := webrtc.SettingEngine{LoggerFactory: quietPion()}
	// Only the target's family, so the test means what it says.
	if a.tgt.v6() {
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP6})
	} else {
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	}
	se.SetIncludeLoopbackCandidate(true)
	se.SetICETimeouts(a.opts.idleTimeout/2, a.opts.idleTimeout, 2*time.Second)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return "", err
	}
	defer pc.Close()

	ordered := true
	dc, err := pc.CreateDataChannel(webrtcLabel, &webrtc.DataChannelInit{Ordered: &ordered})
	if err != nil {
		return "", err
	}
	opened := make(chan struct{})
	verdict := make(chan string, 1)
	drained := make(chan struct{}, 1)
	failed := make(chan struct{})
	var once sync.Once
	dc.OnOpen(func() { close(opened) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		select {
		case verdict <- string(m.Data):
		default:
		}
	})
	dc.SetBufferedAmountLowThreshold(rtcBuffered / 2)
	dc.OnBufferedAmountLow(func() {
		select {
		case drained <- struct{}{}:
		default:
		}
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed {
			once.Do(func() { close(failed) })
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return "", err
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		return "", err
	}
	select {
	case <-gathered:
	case <-time.After(a.opts.connectTimeout):
	}

	// Signaling: offer in, answer out, over HTTPS.
	tr := a.httpTransport(a.tlsConfig("h2", "http/1.1"))
	tr.ForceAttemptHTTP2 = true
	defer tr.CloseIdleConnections()
	body, _ := json.Marshal(pc.LocalDescription())
	req, err := http.NewRequestWithContext(a.traced(a.ctx), http.MethodPost, "https://"+a.hostport+webrtcPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * a.opts.connectTimeout}).Do(req)
	if err != nil {
		return "", a.httpError(err)
	}
	answerBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err := a.checkMarker(resp, answerBody); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", &refusedError{fmt.Sprintf("signaling: %s: %s", resp.Status, oneLine(strings.TrimSpace(string(answerBody))))}
	}
	var answer webrtc.SessionDescription
	if err := json.Unmarshal(answerBody, &answer); err != nil {
		return "", fmt.Errorf("signaling: bad answer: %w", err)
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		return "", fmt.Errorf("signaling: %w", err)
	}

	// ICE, DTLS and SCTP, within -connect-timeout.
	select {
	case <-opened:
	case <-failed:
		return "", rtcUnreachable(a, answer.SDP, "failed")
	case <-time.After(a.opts.connectTimeout):
		return "", rtcUnreachable(a, answer.SDP, fmt.Sprintf("did not come up within %s", a.opts.connectTimeout))
	case <-a.ctx.Done():
		return "", a.ctx.Err()
	}
	a.guard.touch()
	detail := "data channel"
	if sctp := pc.SCTP(); sctp != nil {
		if pair, err := sctp.Transport().ICETransport().GetSelectedCandidatePair(); err == nil && pair != nil {
			detail = fmt.Sprintf("ICE %s %s -> %s", pair.Local.Protocol, net.JoinHostPort(pair.Local.Address, strconv.Itoa(int(pair.Local.Port))),
				net.JoinHostPort(pair.Remote.Address, strconv.Itoa(int(pair.Remote.Port))))
		}
	}

	src := a.source()
	buf := make([]byte, rtcMessage)
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			if err := dc.Send(append([]byte(nil), buf[:n]...)); err != nil {
				return detail, fmt.Errorf("sending failed: %w", err)
			}
			for dc.BufferedAmount() > rtcBuffered {
				select {
				case <-drained:
				case v := <-verdict:
					return detail, verdictText(v)
				case <-failed:
					return detail, errors.New("the WebRTC connection failed")
				case <-a.ctx.Done():
					return detail, a.ctx.Err()
				}
			}
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return detail, rerr
		}
	}
	select {
	case v := <-verdict:
		return detail, verdictText(v)
	case <-failed:
		return detail, errors.New("the WebRTC connection failed before the server confirmed delivery")
	case <-a.ctx.Done():
		return detail, a.ctx.Err()
	}
}

// rtcUnreachable explains a session that signaled fine but never connected:
// the media path (UDP) is what is blocked.
func rtcUnreachable(a *attempt, sdp, what string) error {
	port := ""
	for _, line := range strings.Split(sdp, "\n") {
		if f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "a=")); len(f) >= 6 && strings.HasPrefix(f[0], "candidate:") && strings.EqualFold(f[2], "udp") {
			port = f[5]
			break
		}
	}
	where := "the server's UDP port"
	if port != "" {
		where = "udp/" + port
	}
	return fmt.Errorf("signaling over tcp/%d worked, but the WebRTC connection (ICE/DTLS over %s) %s: UDP blocked?", a.port, where, what)
}

// rtcServer answers offers on the HTTPS listener; all sessions share one UDP
// port for their media (ICE UDP mux).
type rtcServer struct {
	s   *Server
	api *webrtc.API
	pc  net.PacketConn
}

func (s *Server) newRTCServer() (*rtcServer, error) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(s.bind, strconv.Itoa(s.webrtcPort)))
	if err != nil {
		return nil, fmt.Errorf("media port: %w", err)
	}
	se := webrtc.SettingEngine{LoggerFactory: quietPion()}
	se.SetICEUDPMux(webrtc.NewICEUDPMux(quietPion().NewLogger("ice"), pc))
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6})
	if len(s.webrtcIPs) > 0 {
		// Behind NAT: advertise these addresses instead of the host's own.
		rule := webrtc.ICEAddressRewriteRule{External: s.webrtcIPs, AsCandidateType: webrtc.ICECandidateTypeHost}
		if err := se.SetICEAddressRewriteRules(rule); err != nil {
			pc.Close()
			return nil, fmt.Errorf("-webrtc-ip: %w", err)
		}
	}
	return &rtcServer{s: s, api: webrtc.NewAPI(webrtc.WithSettingEngine(se)), pc: pc}, nil
}

func (r *rtcServer) close() { r.pc.Close() }

func (r *rtcServer) handleOffer(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST an SDP offer", http.StatusMethodNotAllowed)
		return
	}
	var offer webrtc.SessionDescription
	if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&offer); err != nil || offer.Type != webrtc.SDPTypeOffer {
		http.Error(w, "bad offer", http.StatusBadRequest)
		return
	}
	pc, err := r.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	remote := req.RemoteAddr
	var closeOnce sync.Once
	closePC := func() { closeOnce.Do(func() { pc.Close() }) }
	opened := make(chan struct{})

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != webrtcLabel {
			return
		}
		pr, pw := io.Pipe()
		dc.OnOpen(func() {
			close(opened)
			r.s.debugf("webrtc", "data channel open with %s", remote)
			go func() {
				verdict := "OK"
				if err := r.s.receive("webrtc", remote, pr); err != nil {
					verdict = "ERR " + oneLine(err.Error())
					pr.CloseWithError(err)
				} else {
					pr.Close()
				}
				_ = dc.SendText(verdict)
				time.AfterFunc(5*time.Second, closePC)
			}()
		})
		// Messages arrive in order; writing blocks until the receiver takes
		// them, which slows the sender down as SCTP flow control does.
		dc.OnMessage(func(m webrtc.DataChannelMessage) { _, _ = pw.Write(m.Data) })
		dc.OnClose(func() { pw.CloseWithError(errors.New("data channel closed")) })
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateDisconnected {
			closePC()
		}
	})
	// A session whose data channel never opens is dropped.
	time.AfterFunc(time.Minute, func() {
		select {
		case <-opened:
		default:
			closePC()
		}
	})

	if err := pc.SetRemoteDescription(offer); err != nil {
		closePC()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		closePC()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		closePC()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	select {
	case <-gathered:
	case <-time.After(5 * time.Second):
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pc.LocalDescription())
}
