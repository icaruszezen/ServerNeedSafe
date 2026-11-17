//go:build !js

package monitor

import (
	"bytes"
	"net/http"
	"time"
)

var nativeWebhookClient = &http.Client{
	Timeout: 6 * time.Second,
}

func defaultWebhookPost(urlClean string, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, urlClean, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "ServerNeedSafe-Monitor/1.0")

	resp, err := nativeWebhookClient.Do(req)
	if err != nil {
		return err
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	return nil
}
