//go:build js && wasm

package monitor

import (
	"sync"
	"syscall/js"
)

var (
	wasmNopOnce sync.Once
	wasmNopFn   js.Func
)

func defaultWebhookPost(urlClean string, body []byte) error {
	fetchFn := js.Global().Get("fetch")
	if fetchFn.Type() != js.TypeFunction {
		return nil
	}
	wasmNopOnce.Do(func() {
		wasmNopFn = js.FuncOf(func(this js.Value, args []js.Value) any { return nil })
	})

	opts := js.Global().Get("Object").New()
	opts.Set("method", "POST")
	opts.Set("cache", "no-store")
	opts.Set("credentials", "omit")
	opts.Set("body", string(body))

	headers := js.Global().Get("Object").New()
	headers.Set("Content-Type", "application/json; charset=utf-8")
	opts.Set("headers", headers)

	promise := js.Global().Call("fetch", urlClean, opts)
	promise.Call("then", wasmNopFn).Call("catch", wasmNopFn)
	return nil
}
