package tlscheck

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/qquuasar/netcheck/internal/result"
)

func Run(result *result.Result) {
	address := net.JoinHostPort(result.Host, result.Port)

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		ServerName: result.Host,
	})
	result.TLSTime = time.Since(start)

	if err != nil {
		result.TLSError = err
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.TLSVersion = versionName(state.Version)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.TLSIssuer = cert.Issuer.CommonName
		result.TLSExpires = cert.NotAfter
	}
}

func versionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
