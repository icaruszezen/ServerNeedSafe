package aiops

import "context"

// StreamResponseMeta carries HTTP status, Content-Type, SSE stream detection status,
// and optional buffered body bytes when an endpoint returns an HTTP error or non-SSE JSON response.
type StreamResponseMeta struct {
	StatusCode  int
	ContentType string
	IsSSE       bool
	RawBody     []byte
}

// HTTPTransport abstracts outbound HTTP/SSE calls so native Go builds use net/http
// while tests can swap or inspect outbound requests cleanly.
type HTTPTransport interface {
	PostStream(ctx context.Context, endpoint string, headers map[string]string, body []byte, onLine func(line string) bool) (*StreamResponseMeta, error)
	PostJSON(ctx context.Context, endpoint string, headers map[string]string, body []byte) (statusCode int, respBody []byte, err error)
	GetJSON(ctx context.Context, endpoint string, headers map[string]string) (statusCode int, respBody []byte, err error)
}
