package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestBlindRelayBidirectionalStreamAndZeroTargetRetention(t *testing.T) {
	// Start dummy TCP echo server simulating an SSH endpoint
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	mgr := NewManager("127.0.0.1:59999")
	srv := httptest.NewServer(http.HandlerFunc(mgr.ServeWebSocket))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	dialer := websocket.Dialer{}
	ws, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS dial: %v", err)
	}
	defer ws.Close()

	// Send initial handshake frame
	hs, _ := json.Marshal(dialHandshakeReq{
		Target:    ln.Addr().String(),
		TimeoutMs: 5000,
	})
	if err := ws.WriteMessage(websocket.TextMessage, hs); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	_, respBytes, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read handshake resp: %v", err)
	}
	var resp dialHandshakeResp
	if err := json.Unmarshal(respBytes, &resp); err != nil || !resp.OK {
		t.Fatalf("expected handshake OK, got %+v (err=%v)", resp, err)
	}

	// Verify active count is 1 and activePipe struct has ZERO string/target fields!
	if mgr.ActiveCount() != 1 {
		t.Fatalf("expected ActiveCount 1, got %d", mgr.ActiveCount())
	}
	pipeType := reflect.TypeOf(activePipe{})
	for i := 0; i < pipeType.NumField(); i++ {
		if pipeType.Field(i).Type.Kind() == reflect.String {
			t.Fatalf("SECURITY FAILURE: activePipe must not store string metadata field %q", pipeType.Field(i).Name)
		}
	}

	// Exchange binary encrypted-like frames
	payload := []byte("SSH-2.0-OpenSSH_Encrypted_Frame_0123456789")
	if err := ws.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	msgType, echoed, err := ws.ReadMessage()
	if err != nil || msgType != websocket.BinaryMessage || !bytes.Equal(echoed, payload) {
		t.Fatalf("binary echo mismatch: type=%d got=%q err=%v", msgType, string(echoed), err)
	}

	// Verify CloseAll tears down active connections immediately
	mgr.CloseAll()
	deadline := time.Now().Add(2 * time.Second)
	for mgr.ActiveCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mgr.ActiveCount() != 0 {
		t.Fatalf("expected ActiveCount 0 after CloseAll, got %d", mgr.ActiveCount())
	}

	// Verify self-port loopback block
	ws2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("WS2 dial: %v", err)
	}
	defer ws2.Close()
	badHS, _ := json.Marshal(dialHandshakeReq{Target: "127.0.0.1:59999"})
	_ = ws2.WriteMessage(websocket.TextMessage, badHS)
	_, badRespBytes, err := ws2.ReadMessage()
	if err != nil {
		t.Fatalf("read bad handshake resp: %v", err)
	}
	var badResp dialHandshakeResp
	_ = json.Unmarshal(badRespBytes, &badResp)
	if badResp.OK {
		t.Fatalf("SECURITY FAILURE: self-port loopback should have been blocked!")
	}
}
