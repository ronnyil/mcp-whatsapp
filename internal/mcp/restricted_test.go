package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/sealjay/mcp-whatsapp/internal/policy"
)

type fakeApprover struct{ calls int }

func (f *fakeApprover) Request(_ context.Context, rcpt, body string) (string, error) {
	f.calls++
	return "NOT SENT YET. approval link", nil
}

func testPolicy(t *testing.T, tools string) *policy.Policy {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.json")
	body := `{"account_label":"T","tools":[` + tools + `],
	  "approval":{"listen":"127.0.0.1:9","public_url":"https://a.example"},
	  "access":{"team_domain":"t.cloudflareaccess.com","approve_aud":"x","allowed_emails":["a@b.c"]}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestRestrictedServer_OnlyAllowlistedTools(t *testing.T) {
	pol := testPolicy(t, `"list_chats","list_messages","send_message"`)
	s := NewRestrictedServer(nil, nil, pol, &fakeApprover{})
	got := s.MCP().ListTools()
	if len(got) != 3 {
		names := []string{}
		for n := range got {
			names = append(names, n)
		}
		t.Fatalf("want exactly 3 tools, got %d: %v", len(got), names)
	}
	for _, banned := range []string{"send_file", "send_reply", "delete_message", "pairing_status", "download_media", "mark_chat_read"} {
		if s.MCP().GetTool(banned) != nil {
			t.Errorf("%s still registered", banned)
		}
	}
}

func TestRestrictedServer_SendMessageOnlyFilesApproval(t *testing.T) {
	pol := testPolicy(t, `"send_message"`)
	ap := &fakeApprover{}
	s := NewRestrictedServer(nil, nil, pol, ap)
	tool := s.MCP().GetTool("send_message")
	if tool == nil {
		t.Fatal("send_message missing")
	}
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{"recipient": "972501111111", "message": "hi"}
	res, err := tool.Handler(context.Background(), req)
	if err != nil || res.IsError {
		t.Fatalf("unexpected result %+v err %v", res, err)
	}
	if ap.calls != 1 {
		t.Fatalf("approver called %d times, want 1", ap.calls)
	}
}

func TestRestrictedServer_NoApproverMeansNoSend(t *testing.T) {
	pol := testPolicy(t, `"send_message"`)
	s := NewRestrictedServer(nil, nil, pol, nil)
	if s.MCP().GetTool("send_message") != nil {
		t.Fatal("send_message registered without an approver")
	}
}
