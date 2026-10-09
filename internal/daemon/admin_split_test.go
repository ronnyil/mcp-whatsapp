package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func do(t *testing.T, method, url string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func startRestricted(t *testing.T, drv pairDriver, healthy func() bool, wrap func(http.Handler) http.Handler) *Server {
	t.Helper()
	s, err := New(Config{
		Addr:       "127.0.0.1:0",
		AdminAddr:  "127.0.0.1:0",
		NoAutoPair: true,
		Driver:     drv,
		Healthy:    healthy,
		MCPWrap:    wrap,
		MCPMount: func(mux *http.ServeMux) {
			mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
		},
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.Run(ctx) }()
	<-s.listenerOK
	return s
}

// In restricted mode no listener serves pairing or reset, and the public
// listener serves nothing but /mcp.
func TestRestricted_NoPairingRoutesAnywhere(t *testing.T) {
	s := startRestricted(t, newFakePairDriver(true), func() bool { return true }, nil)
	pub := "http://" + s.BoundAddr()
	adm := "http://" + s.AdminBoundAddr()
	for _, base := range []string{pub, adm} {
		for _, path := range []string{"/pair", "/pair/qr.png", "/pair/reset", "/approve", "/a/x"} {
			for _, m := range []string{http.MethodGet, http.MethodPost} {
				if code := do(t, m, base+path); code != http.StatusNotFound {
					t.Errorf("%s %s%s: want 404, got %d", m, base, path, code)
				}
			}
		}
	}
	if code := do(t, http.MethodGet, pub+"/healthz"); code != http.StatusNotFound {
		t.Errorf("public /healthz: want 404, got %d", code)
	}
	if code := do(t, http.MethodGet, adm+"/healthz"); code != http.StatusOK {
		t.Errorf("admin /healthz: want 200, got %d", code)
	}
	if code := do(t, http.MethodPost, adm+"/healthz"); code != http.StatusMethodNotAllowed {
		t.Errorf("admin POST /healthz: want 405, got %d", code)
	}
	if code := do(t, http.MethodPost, adm+"/mcp"); code != http.StatusNotFound {
		t.Errorf("admin /mcp: want 404, got %d", code)
	}
}

func TestRestricted_HealthReportsDisconnected(t *testing.T) {
	var up atomic.Bool
	s := startRestricted(t, newFakePairDriver(true), up.Load, nil)
	adm := "http://" + s.AdminBoundAddr() + "/healthz"
	if code := do(t, http.MethodGet, adm); code != http.StatusServiceUnavailable {
		t.Errorf("want 503 while disconnected, got %d", code)
	}
	up.Store(true)
	if code := do(t, http.MethodGet, adm); code != http.StatusOK {
		t.Errorf("want 200 when connected, got %d", code)
	}
}

// MCPWrap guards every route on the public listener.
func TestRestricted_MCPWrapGuardsMCP(t *testing.T) {
	deny := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
	s := startRestricted(t, newFakePairDriver(true), func() bool { return true }, deny)
	if code := do(t, http.MethodPost, "http://"+s.BoundAddr()+"/mcp"); code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

type countingDriver struct {
	*fakePairDriver
	pairings atomic.Int32
}

func (c *countingDriver) StartPairing(ctx context.Context, onQR func(string), onSuccess func()) error {
	c.pairings.Add(1)
	return c.fakePairDriver.StartPairing(ctx, onQR, onSuccess)
}

func TestRestricted_UnpairedDoesNotStartQRPairing(t *testing.T) {
	drv := &countingDriver{fakePairDriver: newFakePairDriver(false)}
	s := startRestricted(t, drv, func() bool { return false }, nil)
	time.Sleep(100 * time.Millisecond)
	if n := drv.pairings.Load(); n != 0 {
		t.Fatalf("StartPairing called %d times with NoAutoPair", n)
	}
	if s.Cache().Paired() {
		t.Fatal("cache reports paired")
	}
}

func TestRestricted_LogoutDoesNotStartQRPairing(t *testing.T) {
	drv := &countingDriver{fakePairDriver: newFakePairDriver(true)}
	s := startRestricted(t, drv, func() bool { return true }, nil)
	waitFor(t, func() bool { return s.Cache().Paired() }, "paired")
	time.Sleep(50 * time.Millisecond)
	drv.outCh <- struct{}{}
	waitFor(t, func() bool { return !s.Cache().Paired() }, "logged out")
	time.Sleep(50 * time.Millisecond)
	if n := drv.pairings.Load(); n != 0 {
		t.Fatalf("StartPairing called %d times after logout with NoAutoPair", n)
	}
}

func TestRestricted_AdminPortInUseFailsStartup(t *testing.T) {
	first := startRestricted(t, newFakePairDriver(true), func() bool { return true }, nil)
	s, _ := New(Config{Addr: "127.0.0.1:0", AdminAddr: first.AdminBoundAddr(), Driver: newFakePairDriver(true)})
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("Run succeeded with admin port taken")
	}
}

func postNote(t *testing.T, url, auth, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestSelfNoteEndpoint(t *testing.T) {
	var got []string
	fail := false
	s, err := New(Config{
		Addr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", NoAutoPair: true,
		Driver: newFakePairDriver(true), Healthy: func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetSelfNote(func(b string) (string, error) {
		if fail {
			return "", errors.New("cap reached")
		}
		got = append(got, b)
		return "SENT", nil
	}, "s3cret")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	<-s.listenerOK
	adm := "http://" + s.AdminBoundAddr() + "/self-note"
	pub := "http://" + s.BoundAddr() + "/self-note"

	for name, auth := range map[string]string{"none": "", "wrong": "Bearer nope", "no scheme": "s3cret"} {
		if c := postNote(t, adm, auth, "x"); c != http.StatusUnauthorized {
			t.Errorf("%s token: %d", name, c)
		}
	}
	if c := postNote(t, pub, "Bearer s3cret", "x"); c != http.StatusNotFound {
		t.Errorf("self-note reachable on public listener: %d", c)
	}
	if c := do(t, http.MethodGet, adm); c != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", c)
	}
	if len(got) != 0 {
		t.Fatalf("sent without valid token: %v", got)
	}
	if c := postNote(t, adm, "Bearer s3cret", "digest text"); c != http.StatusOK || len(got) != 1 || got[0] != "digest text" {
		t.Fatalf("valid post: %d %v", c, got)
	}
	fail = true
	if c := postNote(t, adm, "Bearer s3cret", "x"); c != http.StatusBadGateway {
		t.Fatalf("send error should be 502, got %d", c)
	}
}

func TestSelfNoteAbsentWithoutToken(t *testing.T) {
	s := startRestricted(t, newFakePairDriver(true), func() bool { return true }, nil)
	if c := postNote(t, "http://"+s.AdminBoundAddr()+"/self-note", "Bearer x", "x"); c != http.StatusNotFound {
		t.Fatalf("self-note exists when not configured: %d", c)
	}
}
