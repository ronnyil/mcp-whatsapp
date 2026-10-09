package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sealjay/mcp-whatsapp/internal/policy"
)

func loadPolicy(t *testing.T, mcpAUD string) *policy.Policy {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.json")
	body := `{"account_label":"x","tools":["list_chats"],"access":{"team_domain":"t.cloudflareaccess.com","allowed_emails":["a@b.c"],"mcp_aud":"` + mcpAUD + `"}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestMCPAuthRefusesUnauthenticated(t *testing.T) {
	if _, err := mcpAuth(loadPolicy(t, ""), ""); err == nil {
		t.Fatal("serve would start with /mcp unauthenticated")
	}
}

func TestMCPAuthModes(t *testing.T) {
	wrap, err := mcpAuth(loadPolicy(t, "aud"), "")
	if err != nil || wrap == nil {
		t.Fatalf("Access JWT mode: wrap=%v err=%v", wrap != nil, err)
	}
	// Token-only mode: the daemon's bearer check guards /mcp, no JWT wrap.
	wrap, err = mcpAuth(loadPolicy(t, ""), "secret")
	if err != nil || wrap != nil {
		t.Fatalf("token mode: wrap=%v err=%v", wrap != nil, err)
	}
}
