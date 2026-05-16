package dnscheck

import (
	"net"
	"time"

	"github.com/qquuasar/netcheck/internal/result"
)

func Run(checkResult *result.Result) {
	start := time.Now()

	ips, err := net.LookupIP(checkResult.Host)
	checkResult.DNSTime = time.Since(start)

	if err != nil {
		checkResult.DNSError = err
		return
	}

	for _, ip := range ips {
		checkResult.DNSAddrs = append(checkResult.DNSAddrs, ip.String())
	}
}
