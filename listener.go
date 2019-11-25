package vcert

import (
	"crypto/tls"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"net"
	"time"
)

// NewListener returns a net.Listener that listens on the standard TLS
// port (443) on all interfaces and returns *tls.Conn connections with
// certificates enrolled via Venafi for the provided domain.
//
// It enables one-line HTTPS servers:
//
//     log.Fatal(http.Serve(vcert.NewListener("example.com"), handler))
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
	for i, d := range domains {
		cert, err := getSimpleCertificate(conn, d)
		if err != nil {
			l.e = err
			return &l
		}
		certs[i] = cert
		certsMap[d] = &certs[i]
	}

	l.conf = &tls.Config{
		Certificates:      certs,
		NameToCertificate: certsMap,
	}
	l.Listener, l.e = net.Listen("tcp", ":443") //todo: parse port from domains
	return &l
}

func getSimpleCertificate(conn endpoint.Connector, cn string) (tls.Certificate, error) {
	req := certificate.Request{}
	request_id, err := conn.RequestCertificate(&req)
	if err != nil {
		return tls.Certificate{}, err
	}
	req.PickupID = request_id
	req.Timeout = time.Minute
	cert, err := conn.RetrieveCertificate(&req)
	if err != nil {
		return tls.Certificate{}, err
	}
	_ = cert //todo: parse
	c := tls.Certificate{}
	return c, nil
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

	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(3 * time.Minute)

	return tls.Server(tcpConn, ln.conf), nil
}

func (ln *listener) Close() error {
	if ln.e != nil {
		return ln.e
	}
	return ln.Listener.Close()
}
