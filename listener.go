package vcert

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
)

// NewListener returns a net.Listener that listens on the first port
// specified in domains list (like "example.com:8443") or on default
// (443) port on all interfaces and returns *tls.Conn connections with
// certificates enrolled via Venafi for the provided domain.
//
// It enables one-line HTTPS servers:
//
//	log.Fatal(http.Serve(vcert.NewListener("example.com"), handler))
//
// The returned listener uses a *tls.Config that enables HTTP/2, and
// should only be used with servers that support HTTP/2.
//
// The returned Listener also enables TCP keep-alives on the accepted
// connections. The returned *tls.Conn are returned before their TLS
// handshake has completed.
func (cfg *Config) NewListener(domains ...string) net.Listener {
	l := listener{}
	conn, err := cfg.NewClient()
	if err != nil {
		l.e = err
		return &l
	}
	certs := make([]tls.Certificate, len(domains))
	certsMap := make(map[string]*tls.Certificate)
	port := ""
	for i, d := range domains {
		parsedHost, parsedPort, err := net.SplitHostPort(d)
		if err == nil {
			if port != "" && parsedPort != port {
				l.e = fmt.Errorf("ports conflict: %v and %v", parsedPort, port)
				return &l
			}
			port = parsedPort
			d = parsedHost
		}
		log.Println("Retrieving certificate for domain", d)
		cert, err := getSimpleCertificate(conn, d)
		if err != nil {
			l.e = err
			return &l
		}
		certs[i] = cert
		certsMap[d] = &certs[i]
	}
	if port == "" {
		port = "443"
	}

	/* #nosec */
	l.conf = &tls.Config{
		Certificates:      certs,
		NameToCertificate: certsMap,
	}
	l.Listener, l.e = net.Listen("tcp", ":"+port)
	log.Println("Starting server on port", port)
	return &l
}

func getSimpleCertificate(conn endpoint.Connector, cn string) (tls.Certificate, error) {
	req := certificate.Request{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, CsrOrigin: certificate.LocalGeneratedCSR}
	zc, err := conn.ReadZoneConfiguration()
	if err != nil {
		return tls.Certificate{}, err
	}
	err = conn.GenerateRequest(zc, &req)
	if err != nil {
		return tls.Certificate{}, err
	}
	requestID, err := conn.RequestCertificate(&req)
	if err != nil {
		return tls.Certificate{}, err
	}
	req.PickupID = requestID
	req.Timeout = time.Minute
	certCollection, err := conn.RetrieveCertificate(&req)
	if err != nil {
		return tls.Certificate{}, err
	}
	err = certCollection.AddPrivateKey(req.PrivateKey, nil)

	if err != nil {
		return tls.Certificate{}, err
	}

	privKey, err := util.DecryptPkcs8PrivateKey(certCollection.PrivateKey, "")
	if err != nil {
		return tls.Certificate{}, err
	}
	certCollection.PrivateKey = privKey

	return certCollection.ToTLSCertificate(), err
}

type listener struct {
	net.Listener
	conf *tls.Config
	e    error
}

func (ln *listener) Accept() (net.Conn, error) {
	if ln.e != nil {
		return nil, ln.e
	}
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tcpConn := conn.(*net.TCPConn)

	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		return nil, err
	}
	err = tcpConn.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		return nil, err
	}
	return tls.Server(tcpConn, ln.conf), nil
}

func (ln *listener) Close() error {
	if ln.e != nil {
		return ln.e
	}
	return ln.Listener.Close()
}
