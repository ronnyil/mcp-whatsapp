package daemon

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// With AdminAddr set, the public listener must not serve pairing or reset.
func TestServer_AdminAddrRemovesPairFromPublicListener(t *testing.T) {
	drv := newFakePairDriver(true)
	s, err := New(Config{
		Addr:      "127.0.0.1:0",
		AdminAddr: "127.0.0.1:0",
		Driver:    drv,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	<-s.listenerOK
	base := "http://" + s.BoundAddr()
	for _, path := range []string{"/pair", "/pair/qr.png", "/pair/reset", "/healthz"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req, _ := http.NewRequest(method, base+path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s on public listener: want 404, got %d", method, path, resp.StatusCode)
			}
		}
	}
}
