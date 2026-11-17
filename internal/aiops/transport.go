package aiops

import "context"

// StreamResponseMeta carries HTTP status, Content-Type, and optional buffered body bytes
// when an endpoint returns a non-SSE JSON response or an HTTP error status.
type StreamResponseMeta struct {
	StatusCode  int
	ContentType string
	RawBody     []byte
}

// HTTPTransport abstracts outbound HTTP/SSE calls so native Go builds use net/http
// while GOOS=js GOARCH=wasm builds use browser Worker fetch() + ReadableStream without importing net/http.
type HTTPTransport interface {
	PostStream(ctx context.Context, endpoint string, headers map[string]string, body []byte, onLine func(line string) bool) (*StreamResponseMeta, error)
	PostJSON(ctx context.Context, endpoint string, headers map[string]string, body []byte) (statusCode int, respBody []byte, err error)
}
