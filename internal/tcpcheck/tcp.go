package tcpcheck

import (
	"net"
	"time"

	"github.com/qquuasar/netcheck/internal/result"
)

func Run(checkResult *result.Result) {
	address := net.JoinHostPort(checkResult.Host, checkResult.Port)

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	checkResult.TCPTime = time.Since(start)

	if err != nil {
		checkResult.TCPError = err
		return
	}

	_ = conn.Close()
}
