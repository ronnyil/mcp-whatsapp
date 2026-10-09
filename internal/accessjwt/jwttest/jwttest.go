// Package jwttest fakes a Cloudflare Access team for tests: it serves a JWKS
// and signs RS256 tokens with keys it can rotate. Test-only.
package jwttest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
)

// Team is a fake Access team: an issuer URL plus a JWKS endpoint.
type Team struct {
	Server  *httptest.Server
	Issuer  string
	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey
	current string
	Fetches int
}

// New starts a fake team with one signing key ("k1").
func New(t *testing.T) *Team {
	t.Helper()
	tm := &Team{keys: map[string]*rsa.PrivateKey{}}
	tm.Server = httptest.NewServer(http.HandlerFunc(tm.serveJWKS))
	t.Cleanup(tm.Server.Close)
	tm.Issuer = tm.Server.URL
	tm.Rotate(t, "k1")
	return tm
}

// Rotate adds a new signing key and makes it current; old keys stay published
// unless Drop is called.
func (tm *Team) Rotate(t *testing.T, kid string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tm.mu.Lock()
	tm.keys[kid], tm.current = k, kid
	tm.mu.Unlock()
}

// Drop unpublishes a key.
func (tm *Team) Drop(kid string) {
	tm.mu.Lock()
	delete(tm.keys, kid)
	tm.mu.Unlock()
}

func (tm *Team) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.Fetches++
	type jwk struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	var out struct {
		Keys []jwk `json:"keys"`
	}
	for kid, k := range tm.keys {
		out.Keys = append(out.Keys, jwk{
			Kid: kid, Kty: "RSA", Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		})
	}
	_ = json.NewEncoder(w).Encode(out)
}

// Verifier returns a verifier for this team.
func (tm *Team) Verifier(aud string, emails ...string) *accessjwt.Verifier {
	return accessjwt.NewWithCertsURL(tm.Issuer, tm.Server.URL+"/cdn-cgi/access/certs", aud, emails)
}

// Claims are the fields tests usually vary.
type Claims struct {
	Iss   string
	Aud   any
	Email string
	Exp   time.Time
}

// Valid returns claims that pass for aud and email.
func (tm *Team) Valid(aud, email string) Claims {
	return Claims{Iss: tm.Issuer, Aud: []string{aud}, Email: email, Exp: time.Now().Add(time.Hour)}
}

// Sign signs claims with the current key.
func (tm *Team) Sign(t *testing.T, c Claims) string {
	tm.mu.Lock()
	kid, key := tm.current, tm.keys[tm.current]
	tm.mu.Unlock()
	return SignWith(t, kid, key, c)
}

// SignWith signs with an arbitrary key and kid (forgeries).
func SignWith(t *testing.T, kid string, key *rsa.PrivateKey, c Claims) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	h := enc(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	p := enc(map[string]any{"iss": c.Iss, "aud": c.Aud, "email": c.Email, "exp": c.Exp.Unix(), "type": "app"})
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}
