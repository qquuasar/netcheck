package httpcheck

import (
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/qquuasar/netcheck/internal/result"
)

func Run(checkResult *result.Result, parsedURL *url.URL) {
	var start time.Time

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		checkResult.HTTPError = err
		return
	}

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			checkResult.HTTPTime = time.Since(start)
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	start = time.Now()
	resp, err := client.Do(req)
	if checkResult.HTTPTime == 0 {
		checkResult.HTTPTime = time.Since(start)
	}

	if err != nil {
		checkResult.HTTPError = err
		return
	}
	defer resp.Body.Close()

	checkResult.HTTPStatus = resp.Status
	checkResult.HTTPServer = resp.Header.Get("Server")
}
