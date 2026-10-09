package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
	"github.com/sealjay/mcp-whatsapp/internal/accessjwt/jwttest"
)

// recordingApprover stands in for approval.Manager: it records what would
// be filed and, like the real one, never sends.
type recordingApprover struct{ requests []string }

func (r *recordingApprover) Request(_ context.Context, rcpt, body string) (string, error) {
	r.requests = append(r.requests, rcpt+"|"+body)
	return "NOT SENT YET. Approval required. https://approve.example/a/x", nil
}

type rpcClient struct {
	t       *testing.T
	url     string
	jwt     string
	session string
	nextID  int
}

func (c *rpcClient) call(method string, params any) (int, map[string]any) {
	c.t.Helper()
	c.nextID++
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, c.url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.jwt != "" {
		req.Header.Set("Cf-Access-Jwt-Assertion", c.jwt)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var raw []byte
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data:") {
				raw = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				break
			}
		}
	} else {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		raw = buf.Bytes()
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		c.t.Fatalf("%s: bad response %q", method, raw)
	}
	return resp.StatusCode, out
}

func (c *rpcClient) initialize() {
	c.t.Helper()
	code, out := c.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "1"},
	})
	if code != http.StatusOK || out["error"] != nil {
		c.t.Fatalf("initialize: %d %v", code, out)
	}
	c.call("notifications/initialized", map[string]any{})
}

func restrictedHTTP(t *testing.T) (*httptest.Server, *jwttest.Team, *recordingApprover) {
	t.Helper()
	team := jwttest.New(t)
	ap := &recordingApprover{}
	pol := testPolicy(t, `"list_chats","list_messages","get_chat","get_message_context","search_contacts","list_groups","get_group_info","get_poll_results","request_sync","get_status","send_message"`)
	s := NewRestrictedServer(nil, nil, pol, ap)
	mux := http.NewServeMux()
	s.AttachHTTP(mux)
	srv := httptest.NewServer(accessjwt.Middleware(team.Verifier("aud-mcp", "me@example.com"), mux))
	t.Cleanup(srv.Close)
	return srv, team, ap
}

func TestHTTP_UnauthenticatedRequestsDenied(t *testing.T) {
	srv, team, _ := restrictedHTTP(t)
	for name, jwt := range map[string]string{
		"no token":           "",
		"approvals audience": team.Sign(t, team.Valid("aud-approvals", "me@example.com")),
		"other identity":     team.Sign(t, team.Valid("aud-mcp", "attacker@example.com")),
	} {
		c := &rpcClient{t: t, url: srv.URL + "/mcp", jwt: jwt}
		if code, _ := c.call("tools/list", map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, code)
		}
	}
}

func TestHTTP_OnlyAllowlistedToolsListedAndCallable(t *testing.T) {
	srv, team, ap := restrictedHTTP(t)
	c := &rpcClient{t: t, url: srv.URL + "/mcp", jwt: team.Sign(t, team.Valid("aud-mcp", "me@example.com"))}
	c.initialize()

	_, out := c.call("tools/list", map[string]any{})
	tools := out["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.(map[string]any)["name"].(string)] = true
	}
	if len(names) != 11 {
		t.Fatalf("listed %d tools: %v", len(names), names)
	}

	// Every write-capable upstream tool must be uncallable, not just hidden.
	for _, name := range []string{"send_file", "send_audio_message", "send_reply", "send_reaction", "send_poll",
		"send_poll_vote", "send_contact_card", "edit_message", "delete_message", "mark_read", "mark_chat_read",
		"create_group", "leave_group", "update_group_participants", "join_group_with_link", "block_contact",
		"set_privacy_setting", "set_status_message", "send_presence", "send_typing", "download_media", "pairing_status"} {
		_, out := c.call("tools/call", map[string]any{"name": name, "arguments": map[string]any{"recipient": "972501111111", "message": "x", "chat_jid": "x"}})
		if out["error"] == nil {
			res, _ := out["result"].(map[string]any)
			if isErr, _ := res["isError"].(bool); !isErr {
				t.Errorf("%s was callable: %v", name, out)
			}
		}
	}

	// No alternate route through MCP resources (Sealjay's media template).
	_, out = c.call("resources/templates/list", map[string]any{})
	if res, ok := out["result"].(map[string]any); ok {
		if tmpl, _ := res["resourceTemplates"].([]any); len(tmpl) != 0 {
			t.Errorf("resource templates exposed: %v", tmpl)
		}
	}
	_, out = c.call("resources/read", map[string]any{"uri": "whatsapp://media/x@s.whatsapp.net/ABC"})
	if out["error"] == nil {
		t.Errorf("media resource readable: %v", out)
	}

	// send_message only files an approval request.
	_, out = c.call("tools/call", map[string]any{"name": "send_message", "arguments": map[string]any{"recipient": "972501111111", "message": "hi"}})
	text := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(text, "NOT SENT YET") || len(ap.requests) != 1 {
		t.Fatalf("send_message result %q, requests %v", text, ap.requests)
	}
}

// A prompt-injected instruction can only make Claude call the tools it has.
// None of them approves anything: the approve endpoint is not an MCP tool
// and is not routed on the MCP handler.
func TestHTTP_NoApprovalPathThroughMCP(t *testing.T) {
	srv, team, _ := restrictedHTTP(t)
	c := &rpcClient{t: t, url: srv.URL + "/mcp", jwt: team.Sign(t, team.Valid("aud-mcp", "me@example.com"))}
	c.initialize()
	_, out := c.call("tools/list", map[string]any{})
	for _, tl := range out["result"].(map[string]any)["tools"].([]any) {
		name := tl.(map[string]any)["name"].(string)
		if strings.Contains(name, "approv") || strings.Contains(name, "confirm") {
			t.Errorf("tool %q looks like an approval path", name)
		}
	}
	for _, path := range []string{"/a/x", "/approve", "/pair/reset"} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, nil)
		req.Header.Set("Cf-Access-Jwt-Assertion", c.jwt)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s on MCP listener: %d", path, resp.StatusCode)
		}
	}
}
