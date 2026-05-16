package check

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/qquuasar/netcheck/internal/dnscheck"
	"github.com/qquuasar/netcheck/internal/httpcheck"
	"github.com/qquuasar/netcheck/internal/result"
	"github.com/qquuasar/netcheck/internal/tcpcheck"
	"github.com/qquuasar/netcheck/internal/tlscheck"
)

func Run(rawTarget string) (*result.Result, error) {
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

	checkResult := &result.Result{
		Target: rawTarget,
		Host:   host,
		Port:   port,
		Scheme: parsedURL.Scheme,
	}

	dnscheck.Run(checkResult)
	tcpcheck.Run(checkResult)

	if parsedURL.Scheme == "https" {
		tlscheck.Run(checkResult)
	}

	httpcheck.Run(checkResult, parsedURL)

	return checkResult, nil
}
