// Package accessjwt verifies the Cf-Access-Jwt-Assertion header that
// Cloudflare Access adds to every request it lets through. Checking it at the
// origin means a misconfigured tunnel route or Access policy fails closed
// instead of silently exposing the listener.
package accessjwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier checks Access JWTs for one Access application (one AUD tag).
type Verifier struct {
	v       *oidc.IDTokenVerifier
	allowed map[string]bool
}

// New builds a verifier for team domain "<team>.cloudflareaccess.com",
// application audience aud, and an allowlist of e-mail addresses.
func New(ctx context.Context, teamDomain, aud string, emails []string) *Verifier {
	issuer := "https://" + strings.TrimPrefix(teamDomain, "https://")
	keys := oidc.NewRemoteKeySet(ctx, issuer+"/cdn-cgi/access/certs")
	allowed := map[string]bool{}
	for _, e := range emails {
		allowed[strings.ToLower(strings.TrimSpace(e))] = true
	}
	return &Verifier{
		v:       oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: aud}),
		allowed: allowed,
	}
}

// Check returns the verified e-mail or an error.
func (a *Verifier) Check(r *http.Request) (string, error) {
	raw := r.Header.Get("Cf-Access-Jwt-Assertion")
	if raw == "" {
		return "", fmt.Errorf("missing Cf-Access-Jwt-Assertion")
	}
	tok, err := a.v.Verify(r.Context(), raw)
	if err != nil {
		return "", fmt.Errorf("access jwt: %w", err)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := tok.Claims(&claims); err != nil {
		return "", fmt.Errorf("access jwt claims: %w", err)
	}
	if !a.allowed[strings.ToLower(claims.Email)] {
		return "", fmt.Errorf("access jwt: %q not allowed", claims.Email)
	}
	return claims.Email, nil
}

// Middleware rejects any request without a valid Access JWT for an allowed
// identity. A nil verifier passes everything through.
func Middleware(a *Verifier, next http.Handler) http.Handler {
	if a == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.Check(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
