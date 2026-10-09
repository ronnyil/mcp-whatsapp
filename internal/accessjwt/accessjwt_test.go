package accessjwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sealjay/mcp-whatsapp/internal/accessjwt"
	"github.com/sealjay/mcp-whatsapp/internal/accessjwt/jwttest"
)

const aud = "aud-mcp"
const me = "me@example.com"

func check(v *accessjwt.Verifier, token string) error {
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	if token != "" {
		r.Header.Set("Cf-Access-Jwt-Assertion", token)
	}
	_, err := v.Check(r)
	return err
}

func TestValidToken(t *testing.T) {
	team := jwttest.New(t)
	v := team.Verifier(aud, "Me@Example.com")
	if err := check(v, team.Sign(t, team.Valid(aud, me))); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestRejections(t *testing.T) {
	team := jwttest.New(t)
	v := team.Verifier(aud, me)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	expired := team.Valid(aud, me)
	expired.Exp = time.Now().Add(-2 * time.Hour)
	wrongIss := team.Valid(aud, me)
	wrongIss.Iss = "https://evil.cloudflareaccess.com"
	wrongAud := team.Valid("aud-approvals", me)
	wrongEmail := team.Valid(aud, "attacker@example.com")
	stringAud := team.Valid(aud, me)
	stringAud.Aud = "something-else"

	valid := team.Sign(t, team.Valid(aud, me))
	parts := strings.Split(valid, ".")
	noneAlg := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + "."
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+team.Issuer+`","aud":["`+aud+`"],"email":"attacker@example.com","exp":9999999999}`)) + "." + parts[2]

	cases := map[string]string{
		"missing":          "",
		"garbage":          "abc",
		"forged signature": jwttest.SignWith(t, "k1", other, team.Valid(aud, me)),
		"unknown kid":      jwttest.SignWith(t, "k9", other, team.Valid(aud, me)),
		"expired":          team.Sign(t, expired),
		"wrong issuer":     team.Sign(t, wrongIss),
		"wrong audience":   team.Sign(t, wrongAud),
		"wrong audience 2": team.Sign(t, stringAud),
		"wrong email":      team.Sign(t, wrongEmail),
		"alg none":         noneAlg,
		"tampered claims":  tampered,
	}
	for name, tok := range cases {
		if err := check(v, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	team := jwttest.New(t)
	v := team.Verifier(aud, me)
	if err := check(v, team.Sign(t, team.Valid(aud, me))); err != nil {
		t.Fatal(err)
	}
	// Cloudflare rotates: new key published, tokens signed with it.
	team.Rotate(t, "k2")
	clock := time.Now().Add(time.Minute) // past the refresh rate limit
	v.SetClock(func() time.Time { return clock })
	if err := check(v, team.Sign(t, team.Valid(aud, me))); err != nil {
		t.Fatalf("token from rotated key rejected: %v", err)
	}
	// Old key withdrawn and cache refreshed hourly: old-key tokens stop working.
	team.Drop("k1")
	clock = clock.Add(2 * time.Hour)
	team.Rotate(t, "k3")
	late := team.Valid(aud, me)
	late.Exp = clock.Add(time.Hour)
	if err := check(v, team.Sign(t, late)); err != nil {
		t.Fatalf("k3 rejected: %v", err)
	}
}

func TestUnknownKidRefreshIsRateLimited(t *testing.T) {
	team := jwttest.New(t)
	v := team.Verifier(aud, me)
	_ = check(v, team.Sign(t, team.Valid(aud, me)))
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	before := team.Fetches
	for i := 0; i < 20; i++ {
		_ = check(v, jwttest.SignWith(t, "nope", other, team.Valid(aud, me)))
	}
	if got := team.Fetches - before; got > 1 {
		t.Fatalf("unknown kid triggered %d JWKS fetches, want at most 1", got)
	}
}

func TestMiddlewareFailsClosed(t *testing.T) {
	team := jwttest.New(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	for name, h := range map[string]http.Handler{
		"nil verifier": accessjwt.Middleware(nil, ok),
		"no token":     accessjwt.Middleware(team.Verifier(aud, me), ok),
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", name, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Cf-Access-Jwt-Assertion", team.Sign(t, team.Valid(aud, me)))
	accessjwt.Middleware(team.Verifier(aud, me), ok).ServeHTTP(rec, r)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("valid request blocked: %d", rec.Code)
	}
}

func TestJWKSUnavailableFailsClosed(t *testing.T) {
	team := jwttest.New(t)
	tok := team.Sign(t, team.Valid(aud, me))
	v := accessjwt.NewWithCertsURL(team.Issuer, "http://127.0.0.1:1/certs", aud, []string{me})
	if err := check(v, tok); err == nil {
		t.Fatal("accepted with keys unreachable")
	}
}

func TestDescribeNeverLeaksSignature(t *testing.T) {
	team := jwttest.New(t)
	tok := team.Sign(t, team.Valid(aud, me))
	d := accessjwt.Describe(tok)
	sig := strings.Split(tok, ".")[2]
	if strings.Contains(d, sig) || !strings.Contains(d, `email="me@example.com"`) || !strings.Contains(d, aud) {
		t.Fatalf("bad description: %s", d)
	}
	if accessjwt.Describe("") != "no assertion header" {
		t.Fatal("empty header not described")
	}
}
