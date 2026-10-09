package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.mau.fi/whatsmeow/types"
)

type fakeLIDs map[string]types.JID

func (f fakeLIDs) GetPNForLID(_ context.Context, lid types.JID) (types.JID, error) {
	if pn, ok := f[lid.User]; ok {
		return pn, nil
	}
	return types.JID{}, errors.New("unknown")
}

func load(t *testing.T, body string) (*Policy, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadRejectsDangerousTools(t *testing.T) {
	for _, tool := range []string{"send_file", "delete_message", "pairing_status", "download_media", "set_privacy_setting"} {
		if _, err := load(t, `{"account_label":"x","tools":["`+tool+`"]}`); err == nil {
			t.Errorf("tool %s was accepted", tool)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	if _, err := load(t, `{"account_label":"x","tools":[],"recipient":[]}`); err == nil {
		t.Error("typo field accepted")
	}
}

func TestSendRequiresApprovalConfig(t *testing.T) {
	if _, err := load(t, `{"account_label":"x","tools":["send_message"]}`); err == nil {
		t.Error("send_message accepted without approval/access config")
	}
}

func TestAuthorize(t *testing.T) {
	p, err := load(t, `{
	  "account_label":"Personal",
	  "tools":["list_chats"],
	  "recipients":[
	    {"name":"Spouse","id":"972501111111"},
	    {"name":"Family","id":"120363000000000001@g.us"}
	  ]}`)
	if err != nil {
		t.Fatal(err)
	}
	pn := types.NewJID("972501111111", types.DefaultUserServer)
	lids := fakeLIDs{"55555": pn}
	ctx := context.Background()

	allowed := []string{
		"972501111111",
		"+972501111111",
		"972501111111@s.whatsapp.net",
		"972501111111:3@s.whatsapp.net", // device suffix stripped
		"55555@lid",                     // LID resolved to the PN
		"120363000000000001@g.us",
	}
	for _, r := range allowed {
		if _, _, err := p.Authorize(ctx, lids, r); err != nil {
			t.Errorf("%s denied: %v", r, err)
		}
	}
	denied := []string{
		"972502222222",
		"66666@lid", // unresolvable LID
		"120363000000000002@g.us",
		"status@broadcast",
		"",
	}
	for _, r := range denied {
		if _, _, err := p.Authorize(ctx, lids, r); err == nil {
			t.Errorf("%s allowed", r)
		}
	}
}

func TestEmptyAllowlistDeniesAll(t *testing.T) {
	p, err := load(t, `{"account_label":"x","tools":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Authorize(context.Background(), nil, "972501111111"); err == nil {
		t.Error("empty allowlist allowed a send")
	}
}
