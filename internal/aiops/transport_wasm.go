//go:build js && wasm

package aiops

import (
	"context"
	"errors"
	"strings"
	"syscall/js"
)

type wasmHTTPTransport struct{}

func newDefaultHTTPTransport() HTTPTransport {
	return &wasmHTTPTransport{}
}

func (t *wasmHTTPTransport) PostStream(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
	body []byte,
	onLine func(line string) bool,
) (*StreamResponseMeta, error) {
	opts := js.Global().Get("Object").New()
	opts.Set("method", "POST")
	opts.Set("cache", "no-store")
	opts.Set("credentials", "omit")
	opts.Set("body", string(body))

	hdrObj := js.Global().Get("Object").New()
	for k, v := range headers {
		hdrObj.Set(k, v)
	}
	opts.Set("headers", hdrObj)

	respVal, err := awaitPromise(js.Global().Call("fetch", endpoint, opts))
	if err != nil {
		return nil, err
	}
	status := respVal.Get("status").Int()
	ct := ""
	if h := respVal.Get("headers"); h.Type() == js.TypeObject && !h.IsNull() && !h.IsUndefined() {
		if cv := h.Call("get", "content-type"); cv.Type() == js.TypeString {
			ct = cv.String()
		}
	}

	meta := &StreamResponseMeta{
		StatusCode:  status,
		ContentType: ct,
	}

	if status >= 400 || !strings.Contains(strings.ToLower(ct), "text/event-stream") {
		raw, rErr := readResponseBytes(respVal, 4*1024*1024)
		if rErr != nil {
			return nil, rErr
		}
		meta.RawBody = raw
		return meta, nil
	}

	bodyVal := respVal.Get("body")
	if !bodyVal.IsUndefined() && !bodyVal.IsNull() && bodyVal.Get("getReader").Type() == js.TypeFunction {
		reader := bodyVal.Call("getReader")
		decoder := js.Global().Get("TextDecoder").New("utf-8")
		streamOpt := js.Global().Get("Object").New()
		streamOpt.Set("stream", true)

		var pending string
		for {
			if ctx.Err() != nil {
				cancelQuietly(reader)
				return meta, ctx.Err()
			}
			step, sErr := awaitPromise(reader.Call("read"))
			if sErr != nil {
				return meta, sErr
			}
			done := step.Get("done").Bool()
			val := step.Get("value")
			if !val.IsUndefined() && !val.IsNull() {
				pending += decoder.Call("decode", val, streamOpt).String()
				for {
					idx := strings.IndexByte(pending, '\n')
					if idx < 0 {
						break
					}
					line := strings.TrimRight(pending[:idx], "\r")
					pending = pending[idx+1:]
					if onLine != nil && !onLine(line) {
						cancelQuietly(reader)
						return meta, nil
					}
				}
			}
			if done {
				pending += decoder.Call("decode").String()
				if rem := strings.TrimRight(pending, "\r\n"); rem != "" && onLine != nil {
					onLine(rem)
				}
				break
			}
		}
		return meta, nil
	}

	// Fallback if ReadableStream is unavailable
	txtVal, err := awaitPromise(respVal.Call("text"))
	if err != nil {
		return meta, err
	}
	for _, line := range strings.Split(txtVal.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if onLine != nil && !onLine(line) {
			break
		}
	}
	return meta, nil
}

func (t *wasmHTTPTransport) PostJSON(
	ctx context.Context,
	endpoint string,
	headers map[string]string,
	body []byte,
) (int, []byte, error) {
	if ctx.Err() != nil {
		return 0, nil, ctx.Err()
	}
	opts := js.Global().Get("Object").New()
	opts.Set("method", "POST")
	opts.Set("cache", "no-store")
	opts.Set("credentials", "omit")
	opts.Set("body", string(body))

	hdrObj := js.Global().Get("Object").New()
	for k, v := range headers {
		hdrObj.Set(k, v)
	}
	opts.Set("headers", hdrObj)

	respVal, err := awaitPromise(js.Global().Call("fetch", endpoint, opts))
	if err != nil {
		return 0, nil, err
	}
	status := respVal.Get("status").Int()
	raw, err := readResponseBytes(respVal, 65536)
	return status, raw, err
}

func readResponseBytes(respVal js.Value, limit int) ([]byte, error) {
	bufVal, err := awaitPromise(respVal.Call("arrayBuffer"))
	if err != nil {
		return nil, err
	}
	u8 := js.Global().Get("Uint8Array").New(bufVal)
	n := u8.Get("byteLength").Int()
	if n > limit {
		n = limit
		u8 = u8.Call("subarray", 0, limit)
	}
	out := make([]byte, n)
	if n > 0 {
		js.CopyBytesToGo(out, u8)
	}
	return out, nil
}

func cancelQuietly(reader js.Value) {
	if reader.Type() != js.TypeObject || reader.IsNull() || reader.IsUndefined() {
		return
	}
	if reader.Get("cancel").Type() != js.TypeFunction {
		return
	}
	nop := js.FuncOf(func(this js.Value, args []js.Value) any { return nil })
	p := reader.Call("cancel")
	p.Call("then", nop).Call("catch", nop)
}

func awaitPromise(promise js.Value) (js.Value, error) {
	type pair struct {
		val js.Value
		err error
	}
	ch := make(chan pair, 1)

	var thenFn, catchFn js.Func
	thenFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		var v js.Value
		if len(args) > 0 {
			v = args[0]
		}
		ch <- pair{val: v}
		return nil
	})
	catchFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		msg := "fetch error"
		if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
			if m := args[0].Get("message"); m.Type() == js.TypeString {
				msg = m.String()
			} else {
				msg = args[0].Call("toString").String()
			}
		}
		ch <- pair{err: errors.New(msg)}
		return nil
	})
	defer thenFn.Release()
	defer catchFn.Release()

	promise.Call("then", thenFn).Call("catch", catchFn)
	r := <-ch
	return r.val, r.err
}
