//go:build js && wasm

package zkclient

import (
	"errors"
	"syscall/js"
)

// NewWasmEngine creates a lightweight WASM Zero-Knowledge Client Engine using browser fetch() directly.
func NewWasmEngine(baseURL string) *Engine {
	return newEngineWithDoer(baseURL, wasmFetchJSON)
}

func wasmFetchJSON(method, fullURL string, reqJSON []byte, bearerToken string, sameOrigin bool) (int, []byte, error) {
	opts := js.Global().Get("Object").New()
	opts.Set("method", method)
	opts.Set("cache", "no-store")
	if sameOrigin {
		opts.Set("credentials", "same-origin")
	} else {
		opts.Set("credentials", "omit")
	}

	headers := js.Global().Get("Object").New()
	if len(reqJSON) > 0 {
		headers.Set("Content-Type", "application/json")
		opts.Set("body", string(reqJSON))
	}
	if bearerToken != "" {
		headers.Set("Authorization", "Bearer "+bearerToken)
	}
	opts.Set("headers", headers)

	respVal, err := awaitJSPromise(js.Global().Call("fetch", fullURL, opts))
	if err != nil {
		return 0, nil, err
	}
	status := respVal.Get("status").Int()

	bufVal, err := awaitJSPromise(respVal.Call("arrayBuffer"))
	if err != nil {
		return status, nil, err
	}
	u8 := js.Global().Get("Uint8Array").New(bufVal)
	n := u8.Get("byteLength").Int()
	out := make([]byte, n)
	if n > 0 {
		js.CopyBytesToGo(out, u8)
	}
	return status, out, nil
}

func awaitJSPromise(promise js.Value) (js.Value, error) {
	type resPair struct {
		val js.Value
		err error
	}
	ch := make(chan resPair, 1)

	var thenFn, catchFn js.Func
	thenFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		var v js.Value
		if len(args) > 0 {
			v = args[0]
		}
		ch <- resPair{val: v}
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
		ch <- resPair{err: errors.New(msg)}
		return nil
	})
	defer thenFn.Release()
	defer catchFn.Release()

	promise.Call("then", thenFn).Call("catch", catchFn)
	r := <-ch
	return r.val, r.err
}
