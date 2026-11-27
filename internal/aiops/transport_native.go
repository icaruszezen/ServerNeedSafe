//go:build !js

package aiops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultStreamDialTimeout           = 20 * time.Second
	defaultStreamTLSHandshakeTimeout   = 15 * time.Second
	defaultStreamResponseHeaderTimeout = 90 * time.Second
	defaultStreamIdleChunkTimeout      = 120 * time.Second
	maxStreamLineBytes                 = 8 * 1024 * 1024 // 8 MiB single SSE line cap
	maxNonSSEBodyBytes                 = 2 * 1024 * 1024
	maxGetJSONBodyBytes                = 24 * 1024 * 1024 // models.dev/api.json can be several MB
)

type nativeHTTPTransport struct {
	streamClient *http.Client
	jsonClient   *http.Client
	idleTimeout  time.Duration
}

func newDefaultHTTPTransport() HTTPTransport {
	baseTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultStreamDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   defaultStreamTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultStreamResponseHeaderTimeout,
		ExpectContinueTimeout: 2 * time.Second,
	}
	return &nativeHTTPTransport{
		// Timeout == 0 on streamClient so long active SSE streams are NEVER cut off by a fixed total timer;
		// instead we enforce connect/header timeouts on Transport and per-chunk idle timeouts during reading.
		streamClient: &http.Client{
			Transport: baseTransport,
			Timeout:   0,
		},
		jsonClient: &http.Client{
			Transport: baseTransport,
			Timeout:   25 * time.Second,
		},
		idleTimeout: defaultStreamIdleChunkTimeout,
	}
}

// readLineWithIdleTimeout reads a single line (up to maxBytes) from r, aborting if no bytes arrive
// within idleTimeout or if ctx is canceled.
func readLineWithIdleTimeout(
	ctx context.Context,
	r *bufio.Reader,
	closer io.Closer,
	idleTimeout time.Duration,
) (string, error) {
	if idleTimeout <= 0 {
		idleTimeout = defaultStreamIdleChunkTimeout
	}
	done := make(chan struct{})
	var timedOut bool
	timer := time.AfterFunc(idleTimeout, func() {
		timedOut = true
		_ = closer.Close()
	})
	defer func() {
		timer.Stop()
		close(done)
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-done:
		}
	}()

	var buf bytes.Buffer
	for {
		frag, isPrefix, err := r.ReadLine()
		if len(frag) > 0 {
			if buf.Len()+len(frag) > maxStreamLineBytes {
				return "", fmt.Errorf("单行 SSE 数据超过上限 (%d bytes)", maxStreamLineBytes)
			}
			buf.Write(frag)
		}
		if err != nil {
			if timedOut {
				return "", fmt.Errorf("模型流式响应空闲超时（超过 %s 未收到新数据）", idleTimeout.Round(time.Second))
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(err, io.EOF) && buf.Len() > 0 {
				return buf.String(), nil
			}
			return "", err
		}
		if !isPrefix {
			return buf.String(), nil
		}
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
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		meta.RawBody = raw
		return meta, nil
	}

	ctLower := strings.ToLower(ct)
	explicitSSE := strings.Contains(ctLower, "text/event-stream")
	reader := bufio.NewReaderSize(resp.Body, 64*1024)

	idle := t.idleTimeout
	if idle <= 0 {
		idle = defaultStreamIdleChunkTimeout
	}

	sawFirstContent := false
	for {
		line, rErr := readLineWithIdleTimeout(ctx, reader, resp.Body, idle)
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			if errors.Is(rErr, context.Canceled) {
				break
			}
			return meta, rErr
		}

		trimmed := strings.TrimSpace(line)
		if !sawFirstContent {
			if trimmed == "" {
				continue
			}
			sawFirstContent = true
			// Detect non-SSE JSON payloads (e.g. an error JSON returned with HTTP 200, or a gateway that ignored stream:true).
			// On the other hand, proxies that emit valid SSE lines ("data:", "event:", ":") with mislabeled Content-Type (e.g. text/plain)
			// are accepted and streamed line-by-line!
			looksLikeSSELine := strings.HasPrefix(trimmed, "data:") ||
				strings.HasPrefix(trimmed, "event:") ||
				strings.HasPrefix(trimmed, ":") ||
				strings.HasPrefix(trimmed, "id:") ||
				strings.HasPrefix(trimmed, "retry:")

			if !explicitSSE && !looksLikeSSELine {
				var rawBuf bytes.Buffer
				rawBuf.WriteString(line)
				rawBuf.WriteByte('\n')
				rest, _ := io.ReadAll(io.LimitReader(reader, maxNonSSEBodyBytes-int64(rawBuf.Len())))
				rawBuf.Write(rest)
				meta.IsSSE = false
				meta.RawBody = rawBuf.Bytes()
				return meta, nil
			}
			meta.IsSSE = true
		}

		if onLine != nil && !onLine(line) {
			break
		}
	}

	if explicitSSE && !sawFirstContent {
		meta.IsSSE = true
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

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, raw, nil
}

func (t *nativeHTTPTransport) GetJSON(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGetJSONBodyBytes))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}
