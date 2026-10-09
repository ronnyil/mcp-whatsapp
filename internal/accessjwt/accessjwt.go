// Package accessjwt verifies the Cf-Access-Jwt-Assertion header that
// Cloudflare Access adds to every request it lets through, including MCP
// requests authenticated with Managed OAuth (Cloudflare resolves the opaque
// OAuth token and forwards a signed assertion to the origin).
//
// Validating it at the origin means a request that did not come through
// Access, such as another local process calling 127.0.0.1 directly or a
// misconfigured tunnel route, fails closed.
//
// Standard library only: RS256 signatures checked against the team's JWKS at
// https://<team>.cloudflareaccess.com/cdn-cgi/access/certs, with cached keys
// refreshed hourly and, rate-limited, on an unknown key ID (key rotation).
package accessjwt

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	leeway          = 60 * time.Second
	refreshInterval = time.Hour
	minRefreshGap   = 30 * time.Second
)

// Verifier checks Access JWTs for one Access application (one AUD tag).
type Verifier struct {
	issuer   string
	certsURL string
	aud      string
	allowed  map[string]bool
	client   *http.Client
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	triedAt   time.Time
}

// New builds a verifier for team domain "<team>.cloudflareaccess.com",
// application audience aud, and an allowlist of e-mail addresses.
func New(teamDomain, aud string, emails []string) *Verifier {
	issuer := "https://" + strings.TrimSuffix(strings.TrimPrefix(teamDomain, "https://"), "/")
	return NewWithCertsURL(issuer, issuer+"/cdn-cgi/access/certs", aud, emails)
}

// NewWithCertsURL is New with an explicit issuer and JWKS URL (tests).
func NewWithCertsURL(issuer, certsURL, aud string, emails []string) *Verifier {
	allowed := map[string]bool{}
	for _, e := range emails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			allowed[e] = true
		}
	}
	return &Verifier{
		issuer:   issuer,
		certsURL: certsURL,
		aud:      aud,
		allowed:  allowed,
		client:   &http.Client{Timeout: 10 * time.Second},
		now:      time.Now,
		keys:     map[string]*rsa.PublicKey{},
	}
}

// SetClock replaces the clock (tests).
func (v *Verifier) SetClock(now func() time.Time) { v.now = now }

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type claims struct {
	Iss   string          `json:"iss"`
	Aud   json.RawMessage `json:"aud"`
	Exp   *float64        `json:"exp"`
	Nbf   *float64        `json:"nbf"`
	Email string          `json:"email"`
}

// Check verifies the request's Access JWT and returns the e-mail it carries.
func (v *Verifier) Check(r *http.Request) (string, error) {
	raw := r.Header.Get("Cf-Access-Jwt-Assertion")
	if raw == "" {
		return "", errors.New("missing Cf-Access-Jwt-Assertion")
	}
	return v.Verify(r.Context(), raw)
}

// Verify checks a raw JWT.
func (v *Verifier) Verify(ctx context.Context, raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed token")
	}
	var h header
	if err := decodePart(parts[0], &h); err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	if h.Alg != "RS256" {
		return "", fmt.Errorf("unsupported alg %q", h.Alg)
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("bad signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return "", errors.New("bad signature")
	}

	var c claims
	if err := decodePart(parts[1], &c); err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	now := v.now()
	if c.Iss != v.issuer {
		return "", fmt.Errorf("wrong issuer %q", c.Iss)
	}
	if !audContains(c.Aud, v.aud) {
		return "", errors.New("wrong audience")
	}
	if c.Exp == nil || now.After(time.Unix(int64(*c.Exp), 0).Add(leeway)) {
		return "", errors.New("expired")
	}
	if c.Nbf != nil && now.Add(leeway).Before(time.Unix(int64(*c.Nbf), 0)) {
		return "", errors.New("not yet valid")
	}
	email := strings.ToLower(c.Email)
	if !v.allowed[email] {
		return "", fmt.Errorf("identity %q not allowed", c.Email)
	}
	return email, nil
}

func decodePart(s string, out any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func audContains(raw json.RawMessage, want string) bool {
	if want == "" || len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// key returns the public key for kid, refreshing the JWKS when the cache is
// stale or the kid is unknown (rate-limited so bad tokens can't hammer it).
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	k, ok := v.keys[kid]
	stale := now.Sub(v.fetchedAt) > refreshInterval
	if ok && !stale {
		return k, nil
	}
	if now.Sub(v.triedAt) >= minRefreshGap || v.triedAt.IsZero() {
		v.triedAt = now
		if keys, err := v.fetch(ctx); err == nil {
			v.keys, v.fetchedAt = keys, now
		} else if !ok {
			return nil, fmt.Errorf("fetch keys: %w", err)
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable keys")
	}
	return keys, nil
}

// Middleware rejects any request without a valid Access JWT for an allowed
// identity with 403. It never passes a request through on error.
func Middleware(v *Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v == nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if _, err := v.Check(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
