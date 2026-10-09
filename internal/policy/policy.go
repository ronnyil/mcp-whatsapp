// Package policy holds the per-account security policy for this fork:
// which MCP tools are exposed, which recipients may ever receive a
// message, and how the approval and Cloudflare Access checks are wired.
//
// The policy file is read once at startup. Nothing reachable over MCP can
// change it: to edit the allowlists you edit the JSON on the server and
// restart the service.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go.mau.fi/whatsmeow/types"

	"github.com/sealjay/mcp-whatsapp/internal/client"
)

// EnableableTools is the complete set of tools this fork will ever expose.
// Everything else Sealjay registers (group admin, block, privacy, presence,
// reactions, edits, deletes, file/voice/poll sends, mark-read, pairing_status,
// download_media, …) is deleted at startup regardless of the policy file.
// send_message is special: under this fork it never sends directly, it only
// files an approval request.
var EnableableTools = map[string]bool{
	"list_chats":          true,
	"list_messages":       true,
	"get_chat":            true,
	"get_message_context": true,
	"search_contacts":     true,
	"list_groups":         true,
	"get_group_info":      true,
	"get_poll_results":    true,
	"request_sync":        true,
	"get_status":          true,
	"view_image":          true,
	"send_message":        true,
}

// Recipient is one allowlisted destination. ID is a phone number in
// international format (digits only, e.g. "972501234567"), a phone-number
// JID ("972501234567@s.whatsapp.net"), a LID ("123…@lid") or a group JID
// ("1203630…@g.us").
type Recipient struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// Access configures Cloudflare Access JWT verification. TeamDomain is
// "<team>.cloudflareaccess.com". Each AUD is the "Application Audience
// (AUD) Tag" of the matching Access application.
type Access struct {
	TeamDomain    string   `json:"team_domain"`
	AllowedEmails []string `json:"allowed_emails"`
	ApproveAUD    string   `json:"approve_aud"`
	// MCPAUD is the AUD tag of the Access application in front of /mcp.
	// Every /mcp request must then carry a valid Access JWT for it, which
	// also stops other local processes from calling 127.0.0.1 directly.
	// It may be empty only when WHATSAPP_MCP_TOKEN is set instead (the
	// request-header option); serve refuses to start with neither.
	MCPAUD string `json:"mcp_aud"`
}

// Approval configures the approval web listener.
type Approval struct {
	Listen     string `json:"listen"`      // e.g. "127.0.0.1:9765"
	PublicURL  string `json:"public_url"`  // e.g. "https://approve-personal.example.com"
	TTLMinutes int    `json:"ttl_minutes"` // pending requests expire after this
}

// Policy is the parsed policy file.
type Policy struct {
	AccountLabel string      `json:"account_label"`
	Tools        []string    `json:"tools"`
	Recipients   []Recipient `json:"recipients"`
	// AutoSendToSelf lets send_message deliver to the account's own number
	// ("Message yourself") immediately, without approval. Every other
	// recipient still needs the allowlist and an approval.
	AutoSendToSelf bool `json:"auto_send_to_self"`
	// AutoSendRecipients are fixed destinations (typically one shared
	// family group) that send_message delivers to immediately, without the
	// allowlist or an approval. Phone numbers or group JIDs only; edited
	// only in this file on the server, never over MCP.
	AutoSendRecipients []Recipient `json:"auto_send_recipients"`
	Approval           Approval    `json:"approval"`
	Access             Access      `json:"access"`

	tools map[string]bool
}

// Load reads and validates a policy file. Any tool outside EnableableTools
// is a hard error, so a typo can never widen the surface.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	p.tools = map[string]bool{}
	for _, t := range p.Tools {
		if !EnableableTools[t] {
			return nil, fmt.Errorf("policy: tool %q cannot be enabled in this build", t)
		}
		p.tools[t] = true
	}
	if p.AccountLabel == "" {
		return nil, fmt.Errorf("policy: account_label is required")
	}
	if p.Access.TeamDomain == "" || len(p.Access.AllowedEmails) == 0 {
		return nil, fmt.Errorf("policy: access.team_domain and access.allowed_emails are required")
	}
	if p.tools["send_message"] {
		if p.Approval.Listen == "" || p.Approval.PublicURL == "" {
			return nil, fmt.Errorf("policy: send_message requires approval.listen and approval.public_url")
		}
		if p.Access.ApproveAUD == "" {
			return nil, fmt.Errorf("policy: send_message requires access.approve_aud")
		}
		if p.Access.ApproveAUD == p.Access.MCPAUD {
			return nil, fmt.Errorf("policy: approve_aud must differ from mcp_aud (separate Access applications)")
		}
	}
	for _, r := range p.AutoSendRecipients {
		if r.Name == "" {
			return nil, fmt.Errorf("policy: auto_send_recipients entry %q needs a name", r.ID)
		}
		// nil resolver: LIDs are rejected, so every entry is unambiguous.
		if _, err := Canonical(context.Background(), nil, r.ID); err != nil {
			return nil, fmt.Errorf("policy: auto_send_recipients entry %q: %v (use a phone number or group JID)", r.Name, err)
		}
	}
	if len(p.AutoSendRecipients) > 0 && !p.tools["send_message"] {
		return nil, fmt.Errorf("policy: auto_send_recipients requires send_message in tools")
	}
	if p.Approval.TTLMinutes <= 0 {
		p.Approval.TTLMinutes = 30
	}
	return &p, nil
}

// ToolAllowed reports whether the named MCP tool should stay registered.
func (p *Policy) ToolAllowed(name string) bool { return p.tools[name] }

// LIDResolver maps a LID to its phone-number JID. whatsmeow's
// Store.LIDs satisfies it.
type LIDResolver interface {
	GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error)
}

// Canonical resolves any recipient form to the one identity used for
// authorisation: a phone-number user JID or a group JID, without device or
// agent suffixes. Anything that cannot be resolved is an error, which the
// caller must treat as a denial.
func Canonical(ctx context.Context, lids LIDResolver, raw string) (types.JID, error) {
	norm, err := client.NormalizeRecipient(raw)
	if err != nil {
		return types.JID{}, err
	}
	var jid types.JID
	if strings.Contains(norm, "@") {
		jid, err = types.ParseJID(norm)
		if err != nil {
			return types.JID{}, fmt.Errorf("recipient: %w", err)
		}
	} else {
		jid = types.NewJID(norm, types.DefaultUserServer)
	}
	jid = jid.ToNonAD()
	switch jid.Server {
	case types.DefaultUserServer, types.GroupServer:
		return jid, nil
	case types.HiddenUserServer:
		if lids == nil {
			return types.JID{}, fmt.Errorf("recipient: cannot resolve LID %s", jid)
		}
		pn, err := lids.GetPNForLID(ctx, jid)
		if err != nil || pn.IsEmpty() {
			return types.JID{}, fmt.Errorf("recipient: no phone number known for LID %s", jid)
		}
		return pn.ToNonAD(), nil
	default:
		return types.JID{}, fmt.Errorf("recipient: unsupported destination type %q", jid.Server)
	}
}

// AutoRecipient reports whether target (already canonical) is one of the
// auto_send_recipients, and returns its display name.
func (p *Policy) AutoRecipient(target types.JID) (string, bool) {
	for _, r := range p.AutoSendRecipients {
		if j, err := Canonical(context.Background(), nil, r.ID); err == nil && j == target {
			return r.Name, true
		}
	}
	return "", false
}

// Authorize resolves raw and checks it against the allowlist. It returns
// the canonical JID and the allowlist entry's display name. Deny by default:
// an empty allowlist, an unresolvable recipient or a non-match is an error.
func (p *Policy) Authorize(ctx context.Context, lids LIDResolver, raw string) (types.JID, string, error) {
	target, err := Canonical(ctx, lids, raw)
	if err != nil {
		return types.JID{}, "", err
	}
	for _, r := range p.Recipients {
		allowed, err := Canonical(ctx, lids, r.ID)
		if err != nil {
			continue // a broken entry never matches
		}
		if allowed == target {
			return target, r.Name, nil
		}
	}
	return types.JID{}, "", fmt.Errorf("recipient %s is not on the send allowlist for %s", target, p.AccountLabel)
}
