package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// alpnRaw is the ALPN protocol for the methods that carry the frame directly
// inside TLS or QUIC, with no HTTP in between (tls, quic).
const alpnRaw = "transfermapexec"

// newSelfSignedCert generates a fresh self-signed certificate in memory each
// time the server starts. Nothing is written to disk. The client skips
// verification, so the certificate's identity does not matter; every TLS-based
// method on the server shares it.
func newSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: appName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// tlsConfig returns a server config using the server's certificate and
// offering the given ALPN protocols.
func (s *Server) tlsConfig(alpn ...string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS13,
	}
}

// tlsConfig returns a client config that ignores certificate errors: the
// server's certificate is self-signed, so the connection is encrypted but the
// server is not authenticated. The ClientHello carries -sni, or -host when
// it is a name.
func (a *attempt) tlsConfig(alpn ...string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // intentional: accept the server's self-signed cert
		ServerName:         a.sniName(),
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS13,
	}
}

// tlsDetail summarizes a negotiated TLS connection for the results table.
func tlsDetail(st tls.ConnectionState) string {
	d := tls.VersionName(st.Version)
	if st.NegotiatedProtocol != "" {
		d += ", ALPN " + st.NegotiatedProtocol
	}
	return d
}
