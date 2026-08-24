package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/msdbg/AgentBurp/internal/core"
	"github.com/msdbg/AgentBurp/internal/models"
)

func testRSAPub() *rsa.PublicKey {
	n, _ := new(big.Int).SetString("e7d2b1c0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0", 16)
	return &rsa.PublicKey{N: n, E: 65537}
}

func spkiDER(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func hs256Sign(secret []byte, header, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64URLEncode(mac.Sum(nil))
}

func fakeJWT(role string) string {
	h := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	p := base64URLEncode([]byte(fmt.Sprintf(`{"sub":"alice@example.com","role":%q}`, role)))
	return h + "." + p + ".sig"
}

// jwtServer serves a protected endpoint and, optionally, a JWKS document.
// With verifyHS256 set, tokens are only accepted when they are HS256-signed
// with the published public key (the algorithm-confusion bug).
func jwtServer(withJWKS, verifyHS256 bool) *httptest.Server {
	nB64 := base64.RawURLEncoding.EncodeToString(testRSAPub().N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(testRSAPub().E)).Bytes())
	mux := http.NewServeMux()
	if withJWKS {
		mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","n":%q,"e":%q}]}`, nB64, eB64)
		})
	}
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken([]models.Header{{Name: "Authorization", Value: r.Header.Get("Authorization")}})
		ok := tok != "" && strings.Contains(tok, ".")
		if ok && verifyHS256 {
			parts := strings.Split(tok, ".")
			if len(parts) != 3 {
				ok = false
			} else {
				hd, err := base64.RawURLEncoding.DecodeString(parts[0])
				if err != nil || !strings.Contains(string(hd), `"HS256"`) {
					ok = false
				} else {
					der := spkiDERBytes(testRSAPub())
					mac := hmac.New(sha256.New, der)
					mac.Write([]byte(parts[0] + "." + parts[1]))
					want := base64URLEncode(mac.Sum(nil))
					ok = want == parts[2]
				}
			}
		}
		if !ok {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"email":"alice@example.com","role":"user"}`)
	})
	return httptest.NewServer(mux)
}

func spkiDERBytes(pub *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return der
}

func seedAndScan(t *testing.T, srv *httptest.Server, method, path string, headers []models.Header, body []byte) (map[string]int, error) {
	t.Helper()
	db, proj := setupTestDB(t)
	defer db.Close()
	seedRequest(t, db, proj, srv, method, path, headers, body)
	var epID string
	db.Conn().QueryRow(`SELECT id FROM endpoints WHERE project_id = ? LIMIT 1`, proj.ID).Scan(&epID)
	allowScope(db, proj)
	jobID, err := core.NewJobStore(db).Create(proj.ID, "scan", map[string]interface{}{"type": "active"})
	if err != nil {
		return nil, err
	}
	summary, err := RunActive(context.Background(), db, proj, jobID, ActiveOptions{EndpointID: epID, Rate: 100})
	if err != nil {
		return nil, err
	}
	return summary.ByCheck, nil
}

func TestProbeJWTKeyConfusion(t *testing.T) {
	srv := jwtServer(true, true)
	defer srv.Close()

	der := spkiDERBytes(testRSAPub())
	forged := hs256Sign(der, base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`)),
		base64URLEncode([]byte(`{"sub":"alice@example.com","role":"user"}`)))

	byCheck, err := seedAndScan(t, srv, "GET", "/api/me",
		[]models.Header{{Name: "Authorization", Value: "Bearer " + forged}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if byCheck["jwt-hs256-confusion"] == 0 {
		t.Errorf("expected jwt-hs256-confusion finding, got %v", byCheck)
	}
}

func TestProbeJWTKeyConfusionNoJWKS(t *testing.T) {
	srv := jwtServer(false, false)
	defer srv.Close()

	tok := fakeJWT("user")
	byCheck, err := seedAndScan(t, srv, "GET", "/api/me",
		[]models.Header{{Name: "Authorization", Value: "Bearer " + tok}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if byCheck["jwt-hs256-confusion"] != 0 {
		t.Errorf("no jwt-hs256-confusion expected without JWKS, got %v", byCheck)
	}
}

func TestProbeAdminAuthz(t *testing.T) {
	// Admin surface that admits any authenticated token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"users":[{"email":"admin@example.com","credit":1000}]}`)
	}))
	defer srv.Close()

	// user-level token → critical BFLAA finding.
	byCheck, err := seedAndScan(t, srv, "GET", "/admin/users/all",
		[]models.Header{{Name: "Authorization", Value: "Bearer " + fakeJWT("user")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if byCheck["admin-authz"] == 0 {
		t.Errorf("expected admin-authz finding for user token, got %v", byCheck)
	}

	// admin-level token → no finding.
	byCheck, err = seedAndScan(t, srv, "GET", "/admin/users/all",
		[]models.Header{{Name: "Authorization", Value: "Bearer " + fakeJWT("admin")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if byCheck["admin-authz"] != 0 {
		t.Errorf("no admin-authz expected for admin token, got %v", byCheck)
	}
}

func TestProbeAuthBypassSkipsPreAuthPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, `{"token":"xxx"}`)
	}))
	defer srv.Close()

	byCheck, err := seedAndScan(t, srv, "POST", "/login",
		[]models.Header{{Name: "Authorization", Value: "Bearer tok"}}, []byte(`{"u":"a","p":"b"}`))
	if err != nil {
		t.Fatal(err)
	}
	if byCheck["auth-bypass"] != 0 {
		t.Errorf("no auth-bypass expected on pre-auth path, got %v", byCheck)
	}
}

func TestJWTRoleClaim(t *testing.T) {
	if got := jwtRoleClaim(fakeJWT("user")); got != "user" {
		t.Errorf("expected role user, got %q", got)
	}
	if got := jwtRoleClaim(fakeJWT("admin")); got != "admin" {
		t.Errorf("expected role admin, got %q", got)
	}
	if got := jwtRoleClaim("not-a-jwt"); got != "" {
		t.Errorf("expected empty role for garbage, got %q", got)
	}
}

func TestAdminSensitiveBody(t *testing.T) {
	if !adminSensitiveBody([]byte(`{"users":[{"email":"a@b.c"}]}`)) {
		t.Error("user listing should be sensitive")
	}
	if !adminSensitiveBody([]byte(`{"orders":[{"id":1}]}`)) {
		t.Error("orders should be sensitive")
	}
	if adminSensitiveBody([]byte(`{"product":"car","price":9}`)) {
		t.Error("plain product data should not be sensitive")
	}
}
