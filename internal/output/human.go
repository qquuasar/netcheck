package output

import (
	"fmt"
	"net"
	"time"

	"github.com/qquuasar/netcheck/internal/result"
)

func PrintHuman(checkResult *result.Result) {
	fmt.Printf("Target: %s\n\n", checkResult.Target)

	fmt.Println("DNS:")
	if checkResult.DNSError != nil {
		fmt.Printf("  error: %v\n\n", checkResult.DNSError)
	} else {
		fmt.Printf("  host: %s\n", checkResult.Host)
		fmt.Printf("  lookup_time: %s\n", checkResult.DNSTime.Round(time.Millisecond))
		fmt.Println("  addresses:")
		for _, addr := range checkResult.DNSAddrs {
			fmt.Printf("    - %s\n", addr)
		}
		fmt.Println()
	}

	fmt.Println("TCP:")
	if checkResult.TCPError != nil {
		fmt.Printf("  error: %v\n\n", checkResult.TCPError)
	} else {
		fmt.Printf("  address: %s\n", net.JoinHostPort(checkResult.Host, checkResult.Port))
		fmt.Printf("  connect_time: %s\n\n", checkResult.TCPTime.Round(time.Millisecond))
	}

	if checkResult.Scheme == "https" {
		fmt.Println("TLS:")
		if checkResult.TLSError != nil {
			fmt.Printf("  error: %v\n\n", checkResult.TLSError)
		} else {
			fmt.Printf("  version: %s\n", checkResult.TLSVersion)
			fmt.Printf("  issuer: %s\n", emptyFallback(checkResult.TLSIssuer, "unknown"))
			fmt.Printf("  expires: %s\n", checkResult.TLSExpires.Format("2006-01-02 15:04:05 MST"))
			fmt.Printf("  handshake_time: %s\n\n", checkResult.TLSTime.Round(time.Millisecond))
		}
	}

	fmt.Println("HTTP:")
	if checkResult.HTTPError != nil {
		fmt.Printf("  error: %v\n", checkResult.HTTPError)
	} else {
		fmt.Printf("  status: %s\n", checkResult.HTTPStatus)
		fmt.Printf("  server: %s\n", emptyFallback(checkResult.HTTPServer, "unknown"))
		fmt.Printf("  first_byte_time: %s\n", checkResult.HTTPTime.Round(time.Millisecond))
	}
}

func emptyFallback(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
