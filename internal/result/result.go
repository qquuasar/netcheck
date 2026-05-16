package result

import "time"

type Result struct {
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
