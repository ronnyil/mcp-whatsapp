package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
	"github.com/sealjay/mcp-whatsapp/internal/approval"
	"github.com/sealjay/mcp-whatsapp/internal/client"
	"github.com/sealjay/mcp-whatsapp/internal/daemon"
	mcpsrv "github.com/sealjay/mcp-whatsapp/internal/mcp"
	"github.com/sealjay/mcp-whatsapp/internal/policy"
	"github.com/sealjay/mcp-whatsapp/internal/security"
	"github.com/sealjay/mcp-whatsapp/internal/store"
)

func runServe(storeDir string, redactor *security.Redactor, args []string) int {
	var (
		addr        string
		allowRemote bool
		policyPath  string
		adminAddr   string
	)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&addr, "addr", "", "HTTP bind address (default: 127.0.0.1:8765, env WHATSAPP_MCP_ADDR)")
	fs.BoolVar(&allowRemote, "allow-remote", false, "allow binding to a non-loopback address")
	fs.StringVar(&policyPath, "policy", "", "policy JSON file (required): tool allowlist, send recipients, approval and Access settings")
	fs.StringVar(&adminAddr, "admin-addr", "127.0.0.1:8865", "loopback address for /pair and /healthz (never expose this)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if policyPath == "" {
		fmt.Fprintln(os.Stderr, "-policy is required in this build")
		return 2
	}
	pol, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	if !isLoopbackAddr(adminAddr) {
		fmt.Fprintln(os.Stderr, "-admin-addr must be a loopback address")
		return 2
	}

	addr = resolveAddr(addr)
	if !allowRemote && !isLoopbackAddr(addr) {
		fmt.Fprintf(os.Stderr, "refusing to bind to non-loopback address %q; pass -allow-remote if you mean it\n", addr)
		return 2
	}

	// When binding to a non-loopback address we require a shared bearer
	// token. Loopback-only operation intentionally keeps no token so local
	// editors and curl can hit the daemon without extra setup.
	// This fork honours WHATSAPP_MCP_TOKEN on loopback too, so a bearer
	// token can be enforced behind a tunnel.
	authToken := os.Getenv("WHATSAPP_MCP_TOKEN")
	if allowRemote {
		if authToken == "" {
			fmt.Fprintln(os.Stderr, "-allow-remote requires WHATSAPP_MCP_TOKEN to be set in the environment")
			return 2
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	lock, err := store.TryLock(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	defer lock.Release()

	absStore, err := filepath.Abs(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve store dir: %v\n", err)
		return 1
	}
	allowedMediaRoot := os.Getenv("WHATSAPP_MCP_MEDIA_ROOT")
	if allowedMediaRoot == "" {
		allowedMediaRoot = filepath.Join(absStore, "uploads")
	}
	allowedMediaRoot = filepath.Clean(allowedMediaRoot)
	if mkErr := os.MkdirAll(allowedMediaRoot, 0o755); mkErr != nil {
		fmt.Fprintf(os.Stderr, "warn: could not create media root %q: %v\n", allowedMediaRoot, mkErr)
	}
	// Operator UX: make the media root obvious on boot so users know where
	// to drop outbound attachments.
	fmt.Fprintf(os.Stderr, "media root: %s (drop outbound files here)\n", allowedMediaRoot)

	st, err := store.Open(storeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		return 1
	}
	defer st.Close()

	c, err := client.New(ctx, client.Config{
		StoreDir:         storeDir,
		Store:            st,
		Logger:           client.NewStderrLogger("Client", "INFO", false),
		AllowedMediaRoot: allowedMediaRoot,
		Redactor:         redactor,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client: %v\n", err)
		return 1
	}

	drv := newProductionDriver(c)

	// The daemon owns the pair cache, so build it first, then hand the cache
	// to the MCP server (so pairing_status can surface the live QR), then
	// mount the MCP HTTP handler back onto the daemon.
	var mcpWrap func(http.Handler) http.Handler
	if pol.Access.MCPAUD != "" {
		v := accessjwt.New(ctx, pol.Access.TeamDomain, pol.Access.MCPAUD, pol.Access.AllowedEmails)
		mcpWrap = func(h http.Handler) http.Handler { return accessjwt.Middleware(v, h) }
	}

	d, err := daemon.New(daemon.Config{
		Addr:      addr,
		Driver:    drv,
		AuthToken: authToken,
		AdminAddr: adminAddr,
		MCPWrap:   mcpWrap,
		Healthy:   c.IsConnected,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon.New: %v\n", err)
		return 1
	}

	var approver mcpsrv.Approver
	if pol.ToolAllowed("send_message") {
		v := accessjwt.New(ctx, pol.Access.TeamDomain, pol.Access.ApproveAUD, pol.Access.AllowedEmails)
		mgr, err := approval.Open(storeDir, pol, c, v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "approvals: %v\n", err)
			return 1
		}
		if !isLoopbackAddr(pol.Approval.Listen) {
			fmt.Fprintln(os.Stderr, "approval.listen must be a loopback address")
			return 2
		}
		approvalSrv := &http.Server{Addr: pol.Approval.Listen, Handler: mgr.Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := approvalSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(os.Stderr, "approval listener: %v\n", err)
				cancel()
			}
		}()
		defer approvalSrv.Close()
		approver = mgr
		fmt.Fprintf(os.Stderr, "approvals on http://%s (public %s)\n", pol.Approval.Listen, pol.Approval.PublicURL)
	}

	mcpServer := mcpsrv.NewRestrictedServer(c, d.Cache(), pol, approver)
	d.SetMCPMount(mcpServer.AttachHTTP)

	fmt.Fprintf(os.Stderr, "whatsapp-mcp (%s) MCP on http://%s/mcp, admin on http://%s\n", pol.AccountLabel, addr, adminAddr)
	if !c.IsLoggedIn() {
		fmt.Fprintln(os.Stderr, "unpaired: stop this service and run 'whatsapp-mcp pair-code <phone>'")
	}
	if err := d.Run(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "daemon: %v\n", err)
		return 1
	}
	return 0
}

// resolveAddr applies the -addr / WHATSAPP_MCP_ADDR / default precedence.
func resolveAddr(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("WHATSAPP_MCP_ADDR"); env != "" {
		return env
	}
	return "127.0.0.1:8765"
}

// isLoopbackAddr reports whether addr's host resolves to a loopback IP.
// Hostnames (including "localhost") are resolved via DNS; all returned
// addresses must be loopback for the check to pass. Non-loopback binds
// require -allow-remote.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// If it parses directly as an IP, check without DNS.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// Resolve hostname and require every address to be loopback.
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}
