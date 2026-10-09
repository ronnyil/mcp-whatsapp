package approval

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt/jwttest"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/policy"
	"go.mau.fi/whatsmeow/types"
)

const (
	me         = "me@example.com"
	approveAUD = "aud-approvals"
	mcpAUD     = "aud-mcp"
	spouse     = "972501111111"
	spouseJID  = "972501111111@s.whatsapp.net"
	publicURL  = "https://approve-personal.example.com"
	ownNum     = "972543968469"
	ownJID     = ownNum + "@s.whatsapp.net"
)

type sent struct{ to, body string }

type fakeSender struct {
	mu        sync.Mutex
	calls     []sent
	own       types.JID
	connected bool
	result    client.SendResult
	onSend    func(ctx context.Context)
}

func (f *fakeSender) IsConnected() bool { return f.connected }
func (f *fakeSender) OwnJID() types.JID { return f.own }
func (f *fakeSender) Send(ctx context.Context, to, body string) client.SendResult {
	if f.onSend != nil {
		f.onSend(ctx)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, sent{to, body})
	return f.result
}
func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type env struct {
	t      *testing.T
	dir    string
	team   *jwttest.Team
	sender *fakeSender
	m      *Manager
	srv    *httptest.Server
}

func writePolicy(t *testing.T, dir string, recipients string) *policy.Policy {
	return writePolicyOpts(t, dir, recipients, false)
}

func writePolicyOpts(t *testing.T, dir string, recipients string, selfSend bool) *policy.Policy {
	t.Helper()
	p := filepath.Join(dir, "policy.json")
	flag := "false"
	if selfSend {
		flag = "true"
	}
	body := `{"account_label":"Personal","tools":["send_message"],"auto_send_to_self":` + flag + `,
	  "recipients":[` + recipients + `],
	  "approval":{"listen":"127.0.0.1:9765","public_url":"` + publicURL + `","ttl_minutes":30},
	  "access":{"team_domain":"x.cloudflareaccess.com","allowed_emails":["` + me + `"],"approve_aud":"` + approveAUD + `","mcp_aud":"` + mcpAUD + `"}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

const spouseEntry = `{"name":"Spouse","id":"` + spouse + `"}`

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), team: jwttest.New(t),
		sender: &fakeSender{connected: true, own: types.NewJID(ownNum, types.DefaultUserServer),
			result: client.SendResult{Success: true, ID: "MSGID"}}}
	e.open(writePolicy(t, e.dir, spouseEntry))
	return e
}

// open (re)starts the manager on the same store, like a service restart.
func (e *env) open(pol *policy.Policy) {
	if e.m != nil {
		e.srv.Close()
		_ = e.m.Close()
	}
	m, err := Open(e.dir, pol, e.sender, nil, e.team.Verifier(approveAUD, me))
	if err != nil {
		e.t.Fatal(err)
	}
	e.m = m
	e.srv = httptest.NewServer(m.Handler())
	e.t.Cleanup(func() { e.srv.Close(); _ = m.Close() })
}

var idRe = regexp.MustCompile(`/a/([0-9a-f]{32})`)
var tokRe = regexp.MustCompile(`name="token" value="([0-9a-f]+)"`)

func (e *env) request(to, body string) string {
	e.t.Helper()
	msg, err := e.m.Request(context.Background(), to, body)
	if err != nil {
		e.t.Fatalf("Request: %v", err)
	}
	if !strings.HasPrefix(msg, "NOT SENT YET") {
		e.t.Fatalf("unexpected tool text %q", msg)
	}
	return idRe.FindStringSubmatch(msg)[1]
}

func (e *env) jwt(aud string) string { return e.team.Sign(e.t, e.team.Valid(aud, me)) }

func (e *env) get(path, jwt string) (int, string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if jwt != "" {
		req.Header.Set("Cf-Access-Jwt-Assertion", jwt)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (e *env) tokenFor(id string) string {
	e.t.Helper()
	code, body, _ := e.get("/a/"+id, e.jwt(approveAUD))
	if code != 200 {
		e.t.Fatalf("GET page: %d", code)
	}
	m := tokRe.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatalf("no token on page:\n%s", body)
	}
	return m[1]
}

func (e *env) post(id, action, token, jwt string, hdr map[string]string) int {
	e.t.Helper()
	form := url.Values{"action": {action}, "token": {token}}
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/a/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if jwt != "" {
		req.Header.Set("Cf-Access-Jwt-Assertion", jwt)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (e *env) status(id string) string {
	e.t.Helper()
	r, err := e.m.Load(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.Status
}

func TestApprovedSendSendsExactlyWhatWasShown(t *testing.T) {
	e := newEnv(t)
	text := "שלום! pick up milk 🥛\nline two"
	id := e.request("+"+spouse, text)
	if e.sender.count() != 0 {
		t.Fatal("Request sent something")
	}
	code, page, _ := e.get("/a/"+id, e.jwt(approveAUD))
	if code != 200 || !strings.Contains(page, spouseJID) || !strings.Contains(page, "Spouse") || !strings.Contains(page, "Personal") {
		t.Fatalf("page missing account/recipient: %d\n%s", code, page)
	}
	if !strings.Contains(page, "שלום! pick up milk 🥛\nline two") {
		t.Fatalf("page does not show the exact text:\n%s", page)
	}
	tok := tokRe.FindStringSubmatch(page)[1]
	if c := e.post(id, "approve", tok, e.jwt(approveAUD), nil); c != http.StatusSeeOther {
		t.Fatalf("approve: %d", c)
	}
	if e.sender.count() != 1 || e.sender.calls[0] != (sent{spouseJID, text}) {
		t.Fatalf("sent %+v, want exactly one send of the displayed recipient and text", e.sender.calls)
	}
	if s := e.status(id); s != StatusSent {
		t.Fatalf("status %s", s)
	}
}

func TestNotAllowlistedNeverStored(t *testing.T) {
	e := newEnv(t)
	for _, to := range []string{"972509999999", "120363000000000009@g.us", "status@broadcast", "123@lid"} {
		if _, err := e.m.Request(context.Background(), to, "hi"); err == nil {
			t.Errorf("%s: request accepted", to)
		}
	}
	var n int
	_ = e.m.db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows stored for denied recipients", n)
	}
}

func TestBadOrMissingApprovalToken(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	for _, tok := range []string{"", "00000000000000000000000000000000", "' OR 1=1 --"} {
		e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	}
	if e.sender.count() != 0 || e.status(id) != StatusPending {
		t.Fatalf("sent=%d status=%s", e.sender.count(), e.status(id))
	}
}

func TestAccessRequiredOnEveryRoute(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	other := e.team.Sign(t, e.team.Valid(approveAUD, "attacker@example.com"))
	for name, jwt := range map[string]string{"none": "", "MCP-audience token": e.jwt(mcpAUD), "other identity": other} {
		if c, _, _ := e.get("/a/"+id, jwt); c != http.StatusForbidden {
			t.Errorf("GET with %s: %d", name, c)
		}
		if c, _, _ := e.get("/", jwt); c != http.StatusForbidden {
			t.Errorf("GET / with %s: %d", name, c)
		}
		if c := e.post(id, "approve", tok, jwt, nil); c != http.StatusForbidden {
			t.Errorf("POST with %s: %d", name, c)
		}
	}
	if e.sender.count() != 0 {
		t.Fatal("unauthenticated approve sent a message")
	}
}

func TestExpiredRequestCannotBeApproved(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	later := time.Now().Add(31 * time.Minute)
	e.m.SetClock(func() time.Time { return later })
	e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	if e.sender.count() != 0 {
		t.Fatal("expired request was sent")
	}
	if _, page, _ := e.get("/a/"+id, e.jwt(approveAUD)); !strings.Contains(page, "<b>expired</b>") || strings.Contains(page, "Approve and send") {
		t.Fatalf("expired page still offers approval:\n%s", page)
	}
}

func TestConcurrentApprovalsSendOnce(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	jwt := e.jwt(approveAUD)
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); e.post(id, "approve", tok, jwt, nil) }()
	}
	wg.Wait()
	if n := e.sender.count(); n != 1 {
		t.Fatalf("%d send attempts, want 1", n)
	}
}

func TestReplayAndRefreshDoNotResend(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	jwt := e.jwt(approveAUD)
	e.post(id, "approve", tok, jwt, nil)
	e.post(id, "approve", tok, jwt, nil) // browser refresh / resubmit
	e.post(id, "reject", tok, jwt, nil)  // late reject can't undo or re-trigger
	if n := e.sender.count(); n != 1 || e.status(id) != StatusSent {
		t.Fatalf("sends=%d status=%s", n, e.status(id))
	}
}

func TestRejectedNeverSends(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	e.post(id, "reject", tok, e.jwt(approveAUD), nil)
	e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	if e.sender.count() != 0 || e.status(id) != StatusRejected {
		t.Fatalf("sends=%d status=%s", e.sender.count(), e.status(id))
	}
}

func TestRecipientRemovedFromAllowlistAfterRequest(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	e.open(writePolicy(t, e.dir, `{"name":"Someone else","id":"972502222222"}`)) // edit + restart
	e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	if e.sender.count() != 0 || e.status(id) != StatusFailed {
		t.Fatalf("sends=%d status=%s", e.sender.count(), e.status(id))
	}
}

func TestPendingSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "after restart")
	tok := e.tokenFor(id)
	e.open(writePolicy(t, e.dir, spouseEntry))
	e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	if e.sender.count() != 1 || e.status(id) != StatusSent {
		t.Fatalf("sends=%d status=%s", e.sender.count(), e.status(id))
	}
}

func TestInterruptedSendBecomesUnknownAndIsNeverRetried(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	// Simulate a crash after the claim, before the outcome was recorded.
	if _, err := e.m.db.Exec(`UPDATE requests SET status='sending' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	e.open(writePolicy(t, e.dir, spouseEntry))
	if s := e.status(id); s != StatusUnknown {
		t.Fatalf("status after restart %s, want unknown", s)
	}
	e.post(id, "approve", tok, e.jwt(approveAUD), nil)
	if e.sender.count() != 0 {
		t.Fatal("interrupted send was retried")
	}
}

func TestSendOutcomes(t *testing.T) {
	cases := []struct {
		name      string
		connected bool
		result    client.SendResult
		want      string
		attempts  int
	}{
		{"disconnected", false, client.SendResult{}, StatusFailed, 0},
		{"rate limited", true, client.SendResult{Message: "rate limited: burst — retry in 5s"}, StatusFailed, 1},
		{"network error", true, client.SendResult{Message: "Error sending message: websocket closed"}, StatusUnknown, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.sender.connected, e.sender.result = c.connected, c.result
			id := e.request(spouse, "hi")
			tok := e.tokenFor(id)
			e.post(id, "approve", tok, e.jwt(approveAUD), nil)
			e.post(id, "approve", tok, e.jwt(approveAUD), nil)
			if s := e.status(id); s != c.want || e.sender.count() != c.attempts {
				t.Fatalf("status=%s attempts=%d, want %s/%d", s, e.sender.count(), c.want, c.attempts)
			}
		})
	}
}

func TestSendContextIndependentOfBrowser(t *testing.T) {
	e := newEnv(t)
	var deadline bool
	var errAtSend error
	e.sender.onSend = func(ctx context.Context) {
		_, deadline = ctx.Deadline()
		errAtSend = ctx.Err()
	}
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	// Drive the handler with a request whose context is already cancelled
	// after the claim would happen: decide() must not use it for the send.
	form := url.Values{"action": {"approve"}, "token": {tok}}
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/a/"+id, strings.NewReader(form.Encode())).WithContext(ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Cf-Access-Jwt-Assertion", e.jwt(approveAUD))
	cancel()
	e.m.Handler().ServeHTTP(httptest.NewRecorder(), r)
	if e.sender.count() != 1 || errAtSend != nil || !deadline {
		t.Fatalf("sends=%d ctxErr=%v deadline=%v", e.sender.count(), errAtSend, deadline)
	}
}

func TestHTMLInjectionIsEscaped(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicy(t, e.dir, `{"name":"<img src=x onerror=alert(1)>","id":"`+spouse+`"}`))
	id := e.request(spouse, `</pre><script>alert(1)</script><form action="https://evil">`)
	_, page, _ := e.get("/a/"+id, e.jwt(approveAUD))
	for _, bad := range []string{"<script>", "<img src=x", `<form action="https://evil"`} {
		if strings.Contains(page, bad) {
			t.Fatalf("unescaped %q in page:\n%s", bad, page)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("message text not shown escaped:\n%s", page)
	}
}

func TestCSRFAndClickjackingProtections(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	tok := e.tokenFor(id)
	jwt := e.jwt(approveAUD)
	if c := e.post(id, "approve", tok, jwt, map[string]string{"Origin": "https://evil.example"}); c != http.StatusForbidden {
		t.Errorf("cross-origin POST: %d", c)
	}
	if c := e.post(id, "approve", tok, jwt, map[string]string{"Sec-Fetch-Site": "cross-site"}); c != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", c)
	}
	if e.sender.count() != 0 {
		t.Fatal("cross-site POST sent a message")
	}
	if c := e.post(id, "approve", tok, jwt, map[string]string{"Origin": publicURL, "Sec-Fetch-Site": "same-origin"}); c != http.StatusSeeOther || e.sender.count() != 1 {
		t.Fatalf("same-origin POST: %d sends=%d", c, e.sender.count())
	}
	_, _, h := e.get("/a/"+id, jwt)
	want := map[string]string{
		"X-Frame-Options": "DENY",
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
	}
	for k, v := range want {
		if h.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, d := range []string{"frame-ancestors 'none'", "default-src 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q missing %q", csp, d)
		}
	}
}

func TestPageLoadsNoExternalResources(t *testing.T) {
	e := newEnv(t)
	id := e.request(spouse, "hi")
	_, page, _ := e.get("/a/"+id, e.jwt(approveAUD))
	for _, ext := range []string{"http://", "https://", "<script", "<img", "<link", "@import"} {
		if strings.Contains(page, ext) {
			t.Errorf("page references %q (would leak the URL via Referer or fetch)", ext)
		}
	}
}

func TestCleanupExpiresAndPurges(t *testing.T) {
	e := newEnv(t)
	pending := e.request(spouse, "secret text 1")
	done := e.request(spouse, "secret text 2")
	e.post(done, "approve", e.tokenFor(done), e.jwt(approveAUD), nil)

	t1 := time.Now().Add(2 * time.Hour)
	e.m.SetClock(func() time.Time { return t1 })
	e.m.Cleanup()
	r, _ := e.m.Load(context.Background(), pending)
	if r.Status != StatusExpired || r.Body != "" {
		t.Fatalf("expired pending: status=%s body=%q", r.Status, r.Body)
	}
	t2 := time.Now().Add(25 * time.Hour)
	e.m.SetClock(func() time.Time { return t2 })
	e.m.Cleanup()
	if r, _ := e.m.Load(context.Background(), done); r.Body != "" {
		t.Fatalf("sent text kept after 24h: %q", r.Body)
	}
	t3 := time.Now().Add(8 * 24 * time.Hour)
	e.m.SetClock(func() time.Time { return t3 })
	e.m.Cleanup()
	var n int
	_ = e.m.db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows left after 8 days", n)
	}
}

func TestPendingCap(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxOpen; i++ {
		e.request(spouse, "x")
	}
	if _, err := e.m.Request(context.Background(), spouse, "one too many"); err == nil {
		t.Fatal("pending cap not enforced")
	}
}

func TestSelfSendIsImmediateWhenEnabled(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicyOpts(t, e.dir, "", true))
	for i, to := range []string{ownNum, "+" + ownNum, ownJID, ownNum + ":35@s.whatsapp.net"} {
		msg, err := e.m.Request(context.Background(), to, "note")
		if err != nil || !strings.HasPrefix(msg, "SENT to yourself") {
			t.Fatalf("%s: msg=%q err=%v", to, msg, err)
		}
		if e.sender.count() != i+1 || e.sender.calls[i] != (sent{ownJID, "note"}) {
			t.Fatalf("%s: sends %+v", to, e.sender.calls)
		}
	}
	var pending, recorded int
	_ = e.m.db.QueryRow(`SELECT COUNT(*) FROM requests WHERE status='pending'`).Scan(&pending)
	_ = e.m.db.QueryRow(`SELECT COUNT(*) FROM requests WHERE decided_by='auto:self' AND status='sent'`).Scan(&recorded)
	if pending != 0 || recorded != 4 {
		t.Fatalf("pending=%d recorded=%d", pending, recorded)
	}
}

func TestSelfSendOffByDefault(t *testing.T) {
	e := newEnv(t) // auto_send_to_self false, allowlist = spouse only
	if _, err := e.m.Request(context.Background(), ownNum, "note"); err == nil {
		t.Fatal("self send allowed without the flag or an allowlist entry")
	}
	if e.sender.count() != 0 {
		t.Fatal("sent")
	}
}

func TestSelfFlagDoesNotOpenOtherRecipients(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicyOpts(t, e.dir, "", true))
	if _, err := e.m.Request(context.Background(), spouse, "hi"); err == nil {
		t.Fatal("non-allowlisted recipient accepted with self flag on")
	}
	e.open(writePolicyOpts(t, e.dir, spouseEntry, true))
	msg, err := e.m.Request(context.Background(), spouse, "hi")
	if err != nil || !strings.HasPrefix(msg, "NOT SENT YET") || e.sender.count() != 0 {
		t.Fatalf("allowlisted other recipient must still need approval: %q %v sends=%d", msg, err, e.sender.count())
	}
}

func TestSelfSendHourlyCap(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicyOpts(t, e.dir, "", true))
	for i := 0; i < maxSelfPerHour; i++ {
		if _, err := e.m.Request(context.Background(), ownNum, "x"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err := e.m.Request(context.Background(), ownNum, "one too many"); err == nil {
		t.Fatal("cap not enforced")
	}
	later := time.Now().Add(61 * time.Minute)
	e.m.SetClock(func() time.Time { return later })
	if _, err := e.m.Request(context.Background(), ownNum, "next hour"); err != nil {
		t.Fatalf("cap did not reset: %v", err)
	}
}

func TestSelfSendUnpairedOrDisconnected(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicyOpts(t, e.dir, "", true))
	e.sender.own = types.JID{} // unpaired: no own identity, so no self match
	if _, err := e.m.Request(context.Background(), ownNum, "x"); err == nil {
		t.Fatal("unpaired self send allowed")
	}
	e.sender.own = types.NewJID(ownNum, types.DefaultUserServer)
	e.sender.connected = false
	if _, err := e.m.Request(context.Background(), ownNum, "x"); err == nil {
		t.Fatal("disconnected self send reported success")
	}
	if e.sender.count() != 0 {
		t.Fatal("sent while unpaired/disconnected")
	}
}

func TestSelfSendAmbiguousFailureNotRetried(t *testing.T) {
	e := newEnv(t)
	e.open(writePolicyOpts(t, e.dir, "", true))
	e.sender.result = client.SendResult{Message: "Error sending message: websocket closed"}
	if _, err := e.m.Request(context.Background(), ownNum, "x"); err == nil || !strings.Contains(err.Error(), "may or may not") {
		t.Fatalf("err=%v", err)
	}
	if e.sender.count() != 1 {
		t.Fatalf("attempts=%d", e.sender.count())
	}
}
