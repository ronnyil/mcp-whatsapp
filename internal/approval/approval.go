// Package approval turns send_message into a two-step operation:
//
//  1. The MCP tool files a pending request (recipient already checked against
//     the allowlist) and returns a link. Nothing is sent.
//  2. A human opens the link behind Cloudflare Access, sees the account,
//     recipient and exact text, and taps Approve. Only then is one send
//     attempted.
//
// Guarantees: at most one send attempt per request (an atomic
// pending→sending claim); the attempted recipient and text are exactly the
// stored ones shown on the page; an attempt whose outcome can't be known is
// recorded as "unknown" and never retried. WhatsApp itself cannot promise
// exactly-once delivery, so neither does this package.
//
// The approval listener is a separate loopback port behind its own Access
// application. Every request must carry a valid Access JWT for that
// application's audience, so neither an MCP token nor a local process can
// approve anything.
package approval

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/whatsmeow/types"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/policy"
)

const autoSelf = "auto:self"

const (
	maxOpen        = 20                 // cap on simultaneously pending requests
	maxBody        = 4096               // characters; WhatsApp allows more, a personal tool doesn't need it
	keepBody       = 24 * time.Hour     // text of finished requests is wiped after this
	keepRow        = 7 * 24 * time.Hour // rows are deleted after this
	defaultTimeout = 45 * time.Second
)

// Statuses.
const (
	StatusPending  = "pending"
	StatusSending  = "sending"
	StatusSent     = "sent"
	StatusFailed   = "failed"  // definitely not sent
	StatusUnknown  = "unknown" // attempt made, outcome unknown; never retried
	StatusRejected = "rejected"
	StatusExpired  = "expired"
)

// Sender is the subset of *client.Client the manager needs.
type Sender interface {
	IsConnected() bool
	Send(ctx context.Context, recipient, message string) client.SendResult
	OwnJID() types.JID
}

// maxSelfPerHour caps automatic "Message yourself" sends.
const maxSelfPerHour = 20

// Checker authenticates a browser request (an *accessjwt.Verifier).
type Checker interface {
	Check(r *http.Request) (string, error)
}

// Manager owns the approvals database and the approval HTTP handler.
type Manager struct {
	db          *sql.DB
	pol         *policy.Policy
	send        Sender
	lids        policy.LIDResolver
	access      Checker
	origin      string // scheme://host of approval.public_url
	now         func() time.Time
	SendTimeout time.Duration
}

// Open creates or opens <storeDir>/approvals.db. Requests left in "sending"
// by a crash are marked "unknown" and are never retried.
func Open(storeDir string, pol *policy.Policy, send Sender, lids policy.LIDResolver, access Checker) (*Manager, error) {
	if access == nil {
		return nil, fmt.Errorf("approval: an access checker is required")
	}
	u, err := url.Parse(pol.Approval.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("approval: bad public_url %q", pol.Approval.PublicURL)
	}
	path := filepath.Join(storeDir, "approvals.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialises the pending→sending claim
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS requests (
		id TEXT PRIMARY KEY,
		token TEXT NOT NULL,
		recipient_jid TEXT NOT NULL,
		recipient_name TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		status TEXT NOT NULL,
		result TEXT NOT NULL DEFAULT '',
		decided_by TEXT NOT NULL DEFAULT '',
		decided_at INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	m := &Manager{
		db: db, pol: pol, send: send, lids: lids, access: access,
		origin: u.Scheme + "://" + u.Host, now: time.Now, SendTimeout: defaultTimeout,
	}
	if _, err := db.Exec(`UPDATE requests SET status=?, result=? WHERE status=?`,
		StatusUnknown, "interrupted while sending: may or may not have been delivered; not retried", StatusSending); err != nil {
		return nil, err
	}
	m.Cleanup()
	return m, nil
}

// SetClock replaces the clock (tests).
func (m *Manager) SetClock(now func() time.Time) { m.now = now }

// Close closes the database.
func (m *Manager) Close() error { return m.db.Close() }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Request is what the send_message tool calls. It never sends.
func (m *Manager) Request(ctx context.Context, rawRecipient, body string) (string, error) {
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("message must not be empty")
	}
	if len([]rune(body)) > maxBody {
		return "", fmt.Errorf("message longer than %d characters", maxBody)
	}
	if m.pol.AutoSendToSelf {
		own := m.send.OwnJID()
		if target, err := policy.Canonical(ctx, m.lids, rawRecipient); err == nil && !own.IsEmpty() && target == own {
			return m.sendToSelf(own, body)
		}
	}
	jid, name, err := m.pol.Authorize(ctx, m.lids, rawRecipient)
	if err != nil {
		return "", err
	}
	now := m.now()
	var open int
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM requests WHERE status=? AND expires_at>?`, StatusPending, now.Unix()).Scan(&open); err != nil {
		return "", err
	}
	if open >= maxOpen {
		return "", fmt.Errorf("too many pending approvals; approve or reject the existing ones first")
	}
	id := randHex(16)
	exp := now.Add(time.Duration(m.pol.Approval.TTLMinutes) * time.Minute)
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO requests (id, token, recipient_jid, recipient_name, body, created_at, expires_at, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, randHex(16), jid.String(), name, body, now.Unix(), exp.Unix(), StatusPending); err != nil {
		return "", err
	}
	return fmt.Sprintf("NOT SENT YET. Approval required. Ask the user to open %s/a/%s to review and approve "+
		"(account: %s, to: %s). The link expires at %s.",
		strings.TrimSuffix(m.pol.Approval.PublicURL, "/"), id, m.pol.AccountLabel, name, exp.Format(time.RFC3339)), nil
}

// Cleanup expires stale pending requests and removes old text and rows.
func (m *Manager) Cleanup() {
	now := m.now().Unix()
	_, _ = m.db.Exec(`UPDATE requests SET status=?, body='' WHERE status=? AND expires_at<=?`, StatusExpired, StatusPending, now)
	_, _ = m.db.Exec(`UPDATE requests SET body='' WHERE status NOT IN (?, ?) AND created_at<=?`,
		StatusPending, StatusSending, now-int64(keepBody/time.Second))
	_, _ = m.db.Exec(`DELETE FROM requests WHERE status<>? AND created_at<=?`, StatusSending, now-int64(keepRow/time.Second))
}

// RunJanitor calls Cleanup hourly until ctx ends.
func (m *Manager) RunJanitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Cleanup()
		}
	}
}

// Row is one request as stored.
type Row struct {
	ID, Token, JID, Name, Body, Status, Result string
	Created, Expires                           time.Time
}

// Load returns a request by ID (tests and the page).
func (m *Manager) Load(ctx context.Context, id string) (*Row, error) {
	var r Row
	var c, e int64
	err := m.db.QueryRowContext(ctx,
		`SELECT id, token, recipient_jid, recipient_name, body, status, result, created_at, expires_at
		 FROM requests WHERE id=?`, id).
		Scan(&r.ID, &r.Token, &r.JID, &r.Name, &r.Body, &r.Status, &r.Result, &c, &e)
	if err != nil {
		return nil, err
	}
	r.Created, r.Expires = time.Unix(c, 0), time.Unix(e, 0)
	return &r, nil
}

// Handler serves the approval pages. Every request must carry a valid
// Cloudflare Access JWT for an allowed e-mail.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", m.list)
	mux.HandleFunc("GET /a/{id}", m.show)
	mux.HandleFunc("POST /a/{id}", m.decide)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		if _, err := m.access.Check(r); err != nil {
			log.Printf("approvals: rejected %s %s: %v; %s", r.Method, r.URL.Path, err, accessjwt.Describe(r.Header.Get("Cf-Access-Jwt-Assertion")))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

var page = template.Must(template.New("p").Parse(`<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Approve WhatsApp message</title>
<style>body{font:16px system-ui,sans-serif;margin:16px;max-width:640px}
.k{color:#666;font-size:13px;margin-top:12px}.v{font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;border:1px solid #ccc;border-radius:8px;padding:12px;font:16px system-ui,sans-serif}
button{font-size:18px;padding:14px;width:100%;margin-top:12px;border-radius:8px;border:1px solid #888}
.ok{background:#1a7f37;color:#fff;border:0}</style></head><body>
{{if .IsList}}<h2>Pending approvals: {{.Account}}</h2>{{range .List}}<p><a href="/a/{{.ID}}">{{.Name}}</a>, expires {{.Expires.Format "15:04"}}</p>{{else}}<p>Nothing pending.</p>{{end}}
{{else}}{{with .Req}}
<h2>Send WhatsApp message?</h2>
<div class="k">From account</div><div class="v">{{$.Account}}</div>
<div class="k">To</div><div class="v">{{.Name}}</div><div class="k">{{.JID}}</div>
<div class="k">Exact text</div><pre>{{.Body}}</pre>
<div class="k">Requested {{.Created.Format "Jan 2 15:04"}}, expires {{.Expires.Format "15:04"}}. Status: <b>{{.Status}}</b>{{if .Result}} ({{.Result}}){{end}}</div>
{{if eq .Status "pending"}}
<form method="post"><input type="hidden" name="token" value="{{.Token}}">
<button class="ok" name="action" value="approve">Approve and send</button>
<button name="action" value="reject">Reject</button></form>{{end}}
{{end}}{{end}}</body></html>`))

func (m *Manager) render(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, data)
}

func (m *Manager) list(w http.ResponseWriter, r *http.Request) {
	rows, err := m.db.QueryContext(r.Context(),
		`SELECT id, recipient_name, expires_at FROM requests WHERE status=? AND expires_at>? ORDER BY created_at`,
		StatusPending, m.now().Unix())
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var list []Row
	for rows.Next() {
		var x Row
		var e int64
		if rows.Scan(&x.ID, &x.Name, &e) == nil {
			x.Expires = time.Unix(e, 0)
			list = append(list, x)
		}
	}
	m.render(w, map[string]any{"Account": m.pol.AccountLabel, "IsList": true, "List": list})
}

func (m *Manager) show(w http.ResponseWriter, r *http.Request) {
	req, err := m.Load(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if req.Status == StatusPending && !m.now().Before(req.Expires) {
		req.Status = StatusExpired
	}
	m.render(w, map[string]any{"Account": m.pol.AccountLabel, "Req": req})
}

// sameOrigin rejects cross-site form posts. Browsers send Origin on POST;
// a present Origin must match the approval page's own origin.
func (m *Manager) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" && o != m.origin {
		return false
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return false
	}
	return true
}

func (m *Manager) setStatus(id, status, result string) {
	_, _ = m.db.Exec(`UPDATE requests SET status=?, result=? WHERE id=?`, status, result, id)
}

func (m *Manager) decide(w http.ResponseWriter, r *http.Request) {
	if !m.sameOrigin(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	back := func() { http.Redirect(w, r, "/a/"+id, http.StatusSeeOther) }
	email, _ := m.access.Check(r)
	token := r.PostFormValue("token")
	if token == "" {
		back()
		return
	}
	now := m.now().Unix()

	switch r.PostFormValue("action") {
	case "reject":
		_, _ = m.db.Exec(`UPDATE requests SET status=?, decided_by=?, decided_at=?, body=''
			WHERE id=? AND token=? AND status=?`, StatusRejected, email, now, id, token, StatusPending)
		back()
		return
	case "approve":
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Atomic claim: only one request can move a row out of 'pending'. From
	// here on nothing depends on the browser connection staying open.
	res, err := m.db.Exec(`UPDATE requests SET status=?, decided_by=?, decided_at=?
		WHERE id=? AND token=? AND status=? AND expires_at>?`,
		StatusSending, email, now, id, token, StatusPending, now)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		back() // already decided, expired, unknown id or wrong token
		return
	}
	m.attempt(id)
	back()
}

// attempt performs the single send for a claimed request.
func (m *Manager) attempt(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), m.SendTimeout)
	defer cancel()
	req, err := m.Load(ctx, id)
	if err != nil {
		m.setStatus(id, StatusFailed, "could not load request; nothing sent")
		return
	}
	// Re-check at send time: the allowlist may have changed since the
	// request was filed. The stored JID must still resolve to itself.
	jid, _, err := m.pol.Authorize(ctx, m.lids, req.JID)
	if err != nil || jid.String() != req.JID {
		m.setStatus(id, StatusFailed, "recipient no longer allowed; nothing sent")
		return
	}
	if !m.send.IsConnected() {
		m.setStatus(id, StatusFailed, "WhatsApp not connected; nothing sent")
		return
	}
	m.record(id, m.send.Send(ctx, req.JID, req.Body))
}

// record stores the outcome of one send attempt and returns the status.
func (m *Manager) record(id string, sr client.SendResult) string {
	switch {
	case sr.Success:
		m.setStatus(id, StatusSent, sr.ID)
		return StatusSent
	case strings.HasPrefix(sr.Message, "rate limited"), strings.HasPrefix(sr.Message, "Not connected"):
		// Refused before anything went on the wire.
		m.setStatus(id, StatusFailed, sr.Message+"; nothing sent")
		return StatusFailed
	default:
		m.setStatus(id, StatusUnknown, "send error, may or may not have been delivered; check WhatsApp; not retried: "+sr.Message)
		return StatusUnknown
	}
}

// SendToSelf delivers a note to the paired account's own chat, under the
// same rules as an MCP self-send: only when auto_send_to_self is on, capped
// per hour, recorded, never retried. Used by the local /self-note endpoint.
func (m *Manager) SendToSelf(body string) (string, error) {
	if !m.pol.AutoSendToSelf {
		return "", fmt.Errorf("auto_send_to_self is off")
	}
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("message must not be empty")
	}
	if len([]rune(body)) > maxBody {
		return "", fmt.Errorf("message longer than %d characters", maxBody)
	}
	own := m.send.OwnJID()
	if own.IsEmpty() {
		return "", fmt.Errorf("not paired")
	}
	return m.sendToSelf(own, body)
}

// sendToSelf delivers a note to the account's own chat without approval
// (auto_send_to_self). It is capped per hour and recorded like any request.
func (m *Manager) sendToSelf(own types.JID, body string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.SendTimeout)
	defer cancel()
	now := m.now()
	var recent int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM requests WHERE decided_by=? AND created_at>?`,
		autoSelf, now.Add(-time.Hour).Unix()).Scan(&recent); err != nil {
		return "", err
	}
	if recent >= maxSelfPerHour {
		return "", fmt.Errorf("not sent: more than %d messages to yourself in the last hour", maxSelfPerHour)
	}
	if !m.send.IsConnected() {
		return "", fmt.Errorf("not sent: WhatsApp not connected")
	}
	id := randHex(16)
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO requests (id, token, recipient_jid, recipient_name, body, created_at, expires_at, status, decided_by, decided_at)
		 VALUES (?, ?, ?, 'Me (Message yourself)', ?, ?, ?, ?, ?, ?)`,
		id, randHex(16), own.String(), body, now.Unix(), now.Unix(), StatusSending, autoSelf, now.Unix()); err != nil {
		return "", err
	}
	switch m.record(id, m.send.Send(ctx, own.String(), body)) {
	case StatusSent:
		return "SENT to yourself (Message yourself chat).", nil
	case StatusFailed:
		return "", fmt.Errorf("not sent to yourself; nothing went out")
	default:
		return "", fmt.Errorf("send to yourself may or may not have gone through; check WhatsApp (not retried)")
	}
}
