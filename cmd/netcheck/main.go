package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"
)

type CheckResult struct {
	Target string
	Host   string
	Port   string
	Scheme string

	DNSAddrs []string
	DNSTime  time.Duration
	DNSError error

	TCPTime  time.Duration
	TCPError error

	TLSTime    time.Duration
	TLSVersion string
	TLSIssuer  string
	TLSExpires time.Time
	TLSError   error

	HTTPStatus string
	HTTPServer string
	HTTPTime   time.Duration
	HTTPError  error
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: netcheck <url>")
		fmt.Println("example: netcheck https://example.com")
		os.Exit(1)
	}

	target := os.Args[1]

	result, err := runCheck(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printResult(result)
}

func runCheck(rawTarget string) (*CheckResult, error) {
	if !strings.Contains(rawTarget, "://") {
		rawTarget = "https://" + rawTarget
	}

	parsedURL, err := url.Parse(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	if parsedURL.Hostname() == "" {
		return nil, fmt.Errorf("missing host in url")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()

	if port == "" {
		switch parsedURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return nil, fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
		}
	}

	result := &CheckResult{
		Target: rawTarget,
		Host:   host,
		Port:   port,
		Scheme: parsedURL.Scheme,
	}

	runDNSCheck(result)
	runTCPCheck(result)

	if parsedURL.Scheme == "https" {
		runTLSCheck(result)
	}

	runHTTPCheck(result, parsedURL)

	return result, nil
}

func runDNSCheck(result *CheckResult) {
	start := time.Now()

	ips, err := net.LookupIP(result.Host)
	result.DNSTime = time.Since(start)

	if err != nil {
		result.DNSError = err
		return
	}

	for _, ip := range ips {
		result.DNSAddrs = append(result.DNSAddrs, ip.String())
	}
}

func runTCPCheck(result *CheckResult) {
	address := net.JoinHostPort(result.Host, result.Port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	result.TCPTime = time.Since(start)

	if err != nil {
		result.TCPError = err
		return
	}

	_ = conn.Close()
}

func runTLSCheck(result *CheckResult) {
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
	result.TLSVersion = tlsVersionName(state.Version)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.TLSIssuer = cert.Issuer.CommonName
		result.TLSExpires = cert.NotAfter
	}
}

func runHTTPCheck(result *CheckResult, parsedURL *url.URL) {
	var start time.Time

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		result.HTTPError = err
		return
	}

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			result.HTTPTime = time.Since(start)
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	start = time.Now()
	resp, err := client.Do(req)
	if result.HTTPTime == 0 {
		result.HTTPTime = time.Since(start)
	}

	if err != nil {
		result.HTTPError = err
		return
	}
	defer resp.Body.Close()

	result.HTTPStatus = resp.Status
	result.HTTPServer = resp.Header.Get("Server")
}

func printResult(result *CheckResult) {
	fmt.Printf("Target: %s\n\n", result.Target)

	fmt.Println("DNS:")
	if result.DNSError != nil {
		fmt.Printf("  error: %v\n\n", result.DNSError)
	} else {
		fmt.Printf("  host: %s\n", result.Host)
		fmt.Printf("  lookup_time: %s\n", result.DNSTime.Round(time.Millisecond))
		fmt.Println("  addresses:")
		for _, addr := range result.DNSAddrs {
			fmt.Printf("    - %s\n", addr)
		}
		fmt.Println()
	}

	fmt.Println("TCP:")
	if result.TCPError != nil {
		fmt.Printf("  error: %v\n\n", result.TCPError)
	} else {
		fmt.Printf("  address: %s\n", net.JoinHostPort(result.Host, result.Port))
		fmt.Printf("  connect_time: %s\n\n", result.TCPTime.Round(time.Millisecond))
	}

	if result.Scheme == "https" {
		fmt.Println("TLS:")
		if result.TLSError != nil {
			fmt.Printf("  error: %v\n\n", result.TLSError)
		} else {
			fmt.Printf("  version: %s\n", result.TLSVersion)
			fmt.Printf("  issuer: %s\n", emptyFallback(result.TLSIssuer, "unknown"))
			fmt.Printf("  expires: %s\n", result.TLSExpires.Format("2006-01-02 15:04:05 MST"))
			fmt.Printf("  handshake_time: %s\n\n", result.TLSTime.Round(time.Millisecond))
		}
	}

	fmt.Println("HTTP:")
	if result.HTTPError != nil {
		fmt.Printf("  error: %v\n", result.HTTPError)
	} else {
		fmt.Printf("  status: %s\n", result.HTTPStatus)
		fmt.Printf("  server: %s\n", emptyFallback(result.HTTPServer, "unknown"))
		fmt.Printf("  first_byte_time: %s\n", result.HTTPTime.Round(time.Millisecond))
	}
}

func tlsVersionName(version uint16) string {
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

func emptyFallback(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
