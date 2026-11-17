//go:build !js

package zkclient

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// NewEngine creates a native Go Zero-Knowledge Client Engine using *http.Client.
func NewEngine(baseURL string, client *http.Client) *Engine {
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	doer := func(method, fullURL string, reqJSON []byte, bearerToken string, _ bool) (int, []byte, error) {
		var bodyReader io.Reader
		if len(reqJSON) > 0 {
			bodyReader = bytes.NewReader(reqJSON)
		}
		req, err := http.NewRequest(method, fullURL, bodyReader)
		if err != nil {
			return 0, nil, err
		}
		if len(reqJSON) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		respBytes, err := io.ReadAll(io.LimitReader(res.Body, 72*1024*1024))
		if err != nil {
			return 0, nil, err
		}
		return res.StatusCode, respBytes, nil
	}
	return newEngineWithDoer(baseURL, doer)
}
