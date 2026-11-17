//go:build !js

package aiops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type nativeHTTPTransport struct {
	streamClient *http.Client
	jsonClient   *http.Client
}

func newDefaultHTTPTransport() HTTPTransport {
	return &nativeHTTPTransport{
		streamClient: &http.Client{Timeout: 180 * time.Second},
		jsonClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (t *nativeHTTPTransport) PostStream(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
	body []byte,
	onLine func(line string) bool,
) (*StreamResponseMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := t.streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	meta := &StreamResponseMeta{
		StatusCode:  resp.StatusCode,
		ContentType: ct,
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		meta.RawBody = raw
		return meta, nil
	}
	if !strings.Contains(strings.ToLower(ct), "text/event-stream") {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		if err != nil {
			return nil, err
		}
		meta.RawBody = raw
		return meta, nil
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		if onLine != nil && !onLine(scanner.Text()) {
			break
		}
	}
	if sErr := scanner.Err(); sErr != nil && !errors.Is(sErr, context.Canceled) {
		return meta, sErr
	}
	return meta, nil
}

func (t *nativeHTTPTransport) PostJSON(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
	body []byte,
) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := t.jsonClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, raw, nil
}
