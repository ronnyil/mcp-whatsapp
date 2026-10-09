// Package approval turns send_message into a two-step operation:
//
//  1. The MCP tool files a pending request (recipient already checked against
//     the allowlist) and returns a one-time link. Nothing is sent.
//  2. A human opens the link behind Cloudflare Access, sees the account,
//     recipient and exact text, and taps Approve. Only then is the message
//     sent, at most once.
//
// The approval listener is a separate loopback port with its own tunnel
// hostname and its own Access application, so an MCP OAuth token cannot
// reach it and no MCP tool can approve anything.
package approval

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/policy"
)

const maxOpen = 20 // cap on simultaneously pending requests

// Manager owns the approvals database and the approval HTTP handler.
type Manager struct {
	db     *sql.DB
	pol    *policy.Policy
	client *client.Client
	access *accessjwt.Verifier
}

// Open creates <storeDir>/approvals.db if needed.
func Open(storeDir string, pol *policy.Policy, c *client.Client, access *accessjwt.Verifier) (*Manager, error) {
	path := filepath.Join(storeDir, "approvals.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // serialises the pending→sending transition
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS requests (
		id TEXT PRIMARY KEY,
		token TEXT NOT NULL,
		recipient_jid TEXT NOT NULL,
		recipient_name TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		status TEXT NOT NULL,          -- pending | sending | sent | failed | rejected
		result TEXT NOT NULL DEFAULT '',
		decided_by TEXT NOT NULL DEFAULT '',
		decided_at INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return &Manager{db: db, pol: pol, client: c, access: access}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Request is what the send_message tool calls. It never sends.
func (m *Manager) Request(ctx context.Context, rawRecipient, body string) (string, error) {
	if body == "" {
		return "", fmt.Errorf("message must not be empty")
	}
	jid, name, err := m.pol.Authorize(ctx, m.client.WA().Store.LIDs, rawRecipient)
	if err != nil {
		return "", err
	}
	now := time.Now()
	var open int
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM requests WHERE status='pending' AND expires_at>?`, now.Unix()).Scan(&open); err != nil {
		return "", err
	}
	if open >= maxOpen {
		return "", fmt.Errorf("too many pending approvals; approve or reject the existing ones first")
	}
	id := randHex(16)
	exp := now.Add(time.Duration(m.pol.Approval.TTLMinutes) * time.Minute)
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO requests (id, token, recipient_jid, recipient_name, body, created_at, expires_at, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
		id, randHex(16), jid.String(), name, body, now.Unix(), exp.Unix()); err != nil {
		return "", err
	}
	return fmt.Sprintf("NOT SENT YET. Approval required. Ask the user to open %s/a/%s to review and approve "+
		"(account: %s, to: %s). The link expires at %s.",
		m.pol.Approval.PublicURL, id, m.pol.AccountLabel, name, exp.Format(time.RFC3339)), nil
}

type row struct {
	ID, Token, JID, Name, Body, Status, Result string
	Created, Expires                           time.Time
}

func (m *Manager) load(ctx context.Context, id string) (*row, error) {
	var r row
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
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		if _, err := m.access.Check(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

var page = template.Must(template.New("p").Parse(`<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve WhatsApp message</title>
<style>body{font:16px system-ui,sans-serif;margin:16px;max-width:640px}
.k{color:#666;font-size:13px;margin-top:12px}.v{font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;border:1px solid #ccc;border-radius:8px;padding:12px;font:16px system-ui,sans-serif}
button{font-size:18px;padding:14px;width:100%;margin-top:12px;border-radius:8px;border:1px solid #888}
.ok{background:#1a7f37;color:#fff;border:0}</style></head><body>
{{if .List}}<h2>Pending approvals: {{.Account}}</h2>{{range .List}}<p><a href="/a/{{.ID}}">{{.Name}}</a>, expires {{.Expires.Format "15:04"}}</p>{{else}}<p>Nothing pending.</p>{{end}}
{{else}}{{with .Req}}
<h2>Send WhatsApp message?</h2>
<div class="k">From account</div><div class="v">{{$.Account}}</div>
<div class="k">To</div><div class="v">{{.Name}}</div><div class="k">{{.JID}}</div>
<div class="k">Exact text</div><pre>{{.Body}}</pre>
<div class="k">Requested {{.Created.Format "Jan 2 15:04"}}, expires {{.Expires.Format "15:04"}}. Status: {{.Status}}{{if .Result}} ({{.Result}}){{end}}</div>
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
		`SELECT id, recipient_name, expires_at FROM requests WHERE status='pending' AND expires_at>? ORDER BY created_at`,
		time.Now().Unix())
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var list []row
	for rows.Next() {
		var x row
		var e int64
		if rows.Scan(&x.ID, &x.Name, &e) == nil {
			x.Expires = time.Unix(e, 0)
			list = append(list, x)
		}
	}
	if list == nil {
		list = []row{} // non-nil so the template takes the list branch
	}
	m.render(w, map[string]any{"Account": m.pol.AccountLabel, "List": list})
}

func (m *Manager) show(w http.ResponseWriter, r *http.Request) {
	req, err := m.load(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if req.Status == "pending" && time.Now().After(req.Expires) {
		req.Status = "expired"
	}
	m.render(w, map[string]any{"Account": m.pol.AccountLabel, "Req": req})
}

func (m *Manager) decide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	email, _ := m.access.Check(r)
	token := r.FormValue("token")
	now := time.Now().Unix()

	if r.FormValue("action") == "reject" {
		_, _ = m.db.ExecContext(ctx,
			`UPDATE requests SET status='rejected', decided_by=?, decided_at=? WHERE id=? AND token=? AND status='pending'`,
			email, now, id, token)
		http.Redirect(w, r, "/a/"+id, http.StatusSeeOther)
		return
	}
	if r.FormValue("action") != "approve" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Atomic claim: only one POST can move a request out of 'pending'.
	res, err := m.db.ExecContext(ctx,
		`UPDATE requests SET status='sending', decided_by=?, decided_at=?
		 WHERE id=? AND token=? AND status='pending' AND expires_at>?`,
		email, now, id, token, now)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n != 1 {
		http.Redirect(w, r, "/a/"+id, http.StatusSeeOther) // already decided, expired or bad token
		return
	}
	req, err := m.load(ctx, id)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	finish := func(status, result string) {
		_, _ = m.db.ExecContext(context.Background(),
			`UPDATE requests SET status=?, result=? WHERE id=?`, status, result, id)
	}
	// Re-check the allowlist at send time: the policy may have changed since
	// the request was filed.
	if _, _, err := m.pol.Authorize(ctx, m.client.WA().Store.LIDs, req.JID); err != nil {
		finish("failed", err.Error())
		http.Redirect(w, r, "/a/"+id, http.StatusSeeOther)
		return
	}
	sr := m.client.Send(ctx, req.JID, req.Body)
	if sr.Success {
		finish("sent", sr.ID)
	} else {
		finish("failed", sr.Message)
	}
	http.Redirect(w, r, "/a/"+id, http.StatusSeeOther)
}
