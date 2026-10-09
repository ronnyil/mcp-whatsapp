// Package mcp wires mark3labs/mcp-go to the internal/client and internal/store
// packages, exposing the WhatsApp bridge over MCP Streamable HTTP.
package mcp

import (
	"context"
	"net/http"
	"sort"

	"github.com/mark3labs/mcp-go/server"

	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/policy"
)

// Approver files a send for human approval. *approval.Manager satisfies it.
type Approver interface {
	Request(ctx context.Context, rawRecipient, body string) (string, error)
}

// pairingCache is the minimal pairing-state surface pairing_status needs.
// *daemon.PairCache satisfies it. The smoke command and tests pass nil, in
// which case pairing_status reports an "error" envelope.
type pairingCache interface {
	Paired() bool
	QR() string
}

// Server holds the MCP server, its bound WhatsApp client, and an optional
// pairing cache (used only by pairing_status).
type Server struct {
	client   *client.Client
	mcp      *server.MCPServer
	cache    pairingCache
	approver Approver // non-nil: send_message files approvals instead of sending
}

// NewServer constructs an MCP server with all tools registered against the
// provided WhatsApp client. cache may be nil (smoke/tests); pairing_status is
// the only tool that consults it.
func NewServer(c *client.Client, cache pairingCache) *Server {
	mcpSrv := server.NewMCPServer(
		"whatsapp",
		"0.5.0",
		server.WithToolCapabilities(true),
	)
	s := &Server{client: c, mcp: mcpSrv, cache: cache}
	s.registerTools()
	s.registerResources()
	return s
}

// NewRestrictedServer is the constructor serve uses in this fork. It
// registers Sealjay's tools, then deletes every tool the policy does not
// allow, so they are neither listed nor callable. The media resource
// template (an alternate route to download_media) is never registered.
// send_message, if allowed, routes through approver and never sends.
func NewRestrictedServer(c *client.Client, cache pairingCache, pol *policy.Policy, approver Approver) *Server {
	mcpSrv := server.NewMCPServer(
		"whatsapp",
		"0.5.0-restricted",
		server.WithToolCapabilities(true),
	)
	s := &Server{client: c, mcp: mcpSrv, cache: cache, approver: approver}
	s.registerTools()
	var drop []string
	for name := range s.mcp.ListTools() {
		if !pol.ToolAllowed(name) {
			drop = append(drop, name)
		}
	}
	sort.Strings(drop)
	s.mcp.DeleteTools(drop...)
	if pol.ToolAllowed("send_message") && approver == nil {
		s.mcp.DeleteTools("send_message") // fail closed
	}
	return s
}

// MCP returns the underlying mcp-go server (tests only).
func (s *Server) MCP() *server.MCPServer { return s.mcp }

// AttachHTTP mounts the MCP Streamable HTTP handler on mux at /mcp. The
// actual listener lifecycle is owned by the caller (internal/daemon).
func (s *Server) AttachHTTP(mux *http.ServeMux) {
	httpHandler := server.NewStreamableHTTPServer(s.mcp)
	mux.Handle("/mcp", httpHandler)
}
