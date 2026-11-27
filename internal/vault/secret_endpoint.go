package vault

import "strings"

// SameEndpointURL reports whether two configured endpoint URLs refer to the same destination after
// trivial normalisation (surrounding whitespace, trailing slashes, ASCII case of scheme/host).
// It guards stored secrets (AI API keys, webhook signing secrets) against being re-used with a
// caller-chosen destination without re-entering them.
func SameEndpointURL(a, b string) bool {
	return normalizeEndpointURL(a) == normalizeEndpointURL(b)
}

func normalizeEndpointURL(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	// Lower-case scheme://host only; paths and query strings are case-sensitive.
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		hostEnd := strings.IndexAny(rest, "/?#")
		if hostEnd < 0 {
			hostEnd = len(rest)
		}
		u = strings.ToLower(u[:i+3+hostEnd]) + rest[hostEnd:]
	}
	return u
}

func normalizeAIProtocol(p AIProtocol) AIProtocol {
	return NormalizeAIProtocol(p)
}
