package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

func main() {
	go jsChallengeServer()
	go rateLimitServer()
	go csrfServer()
	go ssoServer()
	go signedAPIServer()
	go sessionExpiryServer()
	go businessStateServer()
	fmt.Println("Gauntlet servers running: 9001 JS challenge, 9002 rate limit, 9003 CSRF, 9004 SSO, 9005 signed API, 9006 session expiry, 9007 business state")
	select {}
}

func jsChallengeServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("challenge")
		if err == nil && cookie.Value == "ok" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "JS challenge passed - welcome")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><head><script>document.cookie="challenge=ok; path=/";</script></head><body>Checking your browser... js challenge please wait. javascript challenge</body></html>`)
	})
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("challenge")
		json.NewEncoder(w).Encode(map[string]interface{}{"challenge_cookie": c})
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9001", mux))
}

func rateLimitServer() {
	type bucket struct {
		count int
		start time.Time
		mu    sync.Mutex
	}
	b := &bucket{start: time.Now()}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if time.Since(b.start) > 10*time.Second {
			b.start = time.Now()
			b.count = 0
		}
		if b.count >= 5 {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "too many requests - rate limit exceeded", 429)
			return
		}
		b.count++
		fmt.Fprintf(w, "ok %d", b.count)
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.count = 0
		b.start = time.Now()
		b.mu.Unlock()
		fmt.Fprintln(w, "reset")
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9002", mux))
}

func csrfServer() {
	var mu sync.Mutex
	tokens := map[string]bool{}
	counter := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counter++
		tok := fmt.Sprintf("csrf-%d", counter)
		tokens[tok] = true
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-CSRF-Token")
		mu.Lock()
		defer mu.Unlock()
		if tok == "" || !tokens[tok] {
			http.Error(w, "csrf token expired or missing", 403)
			return
		}
		delete(tokens, tok)
		fmt.Fprintln(w, "submitted ok")
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9003", mux))
}

func ssoServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9004/sso/authorize", 302)
	})
	mux.HandleFunc("/sso/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sso_code", Value: "authcode123", Path: "/"})
		http.Redirect(w, r, "http://127.0.0.1:9004/callback?code=authcode123", 302)
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "authcode123" {
			http.Error(w, "invalid code", 400)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sso_ok", Path: "/"})
		fmt.Fprintln(w, "dashboard - SSO success")
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || c.Value != "sso_ok" {
			http.Error(w, "unauthorized", 401)
			return
		}
		fmt.Fprintln(w, "welcome to dashboard")
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9004", mux))
}

func signedAPIServer() {
	secret := "supersecret"
	compute := func(payload string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(payload))
		return hex.EncodeToString(mac.Sum(nil))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<html><script>window.sign = function(payload){ // simplified HMAC via JS - for demo, just return known value
			return "dummy";
		}
		window.app = { security: { sign: function(path, body){ return {signature: "abc123", timestamp: Date.now()}; } } };
		</script>Signer page</html>`)
	})
	mux.HandleFunc("/api/order", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payload := string(body)
		sig := r.Header.Get("X-Signature")
		expected := compute(payload)
		if sig != expected && sig != "abc123" {
			http.Error(w, "invalid signature - request tampering", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "order placed", "payload": payload})
	})
	mux.HandleFunc("/compute", func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("payload")
		json.NewEncoder(w).Encode(map[string]string{"signature": compute(payload)})
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9005", mux))
}

func sessionExpiryServer() {
	type sess struct {
		token   string
		created time.Time
	}
	var mu sync.Mutex
	sessions := map[string]sess{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		tok := fmt.Sprintf("tok-%d", time.Now().UnixNano())
		mu.Lock()
		sessions[tok] = sess{token: tok, created: time.Now()}
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"access_token": tok})
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := ""
		fmt.Sscanf(auth, "Bearer %s", &token)
		mu.Lock()
		s, ok := sessions[token]
		mu.Unlock()
		if !ok {
			http.Error(w, "token invalid", 401)
			return
		}
		if time.Since(s.created) > 10*time.Second {
			http.Error(w, "token expired", 401)
			return
		}
		fmt.Fprintln(w, "protected data")
	})
	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		old := r.URL.Query().Get("token")
		mu.Lock()
		s, ok := sessions[old]
		mu.Unlock()
		if !ok {
			http.Error(w, "invalid token", 401)
			return
		}
		newTok := fmt.Sprintf("tok-%d", time.Now().UnixNano())
		mu.Lock()
		delete(sessions, old)
		sessions[newTok] = sess{token: newTok, created: time.Now()}
		mu.Unlock()
		_ = s
		json.NewEncoder(w).Encode(map[string]string{"access_token": newTok})
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9006", mux))
}

func businessStateServer() {
	type cart struct {
		items []string
	}
	var mu sync.Mutex
	carts := map[string]*cart{}
	counter := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/cart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		mu.Lock()
		counter++
		id := fmt.Sprintf("cart-%d", counter)
		carts[id] = &cart{}
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"cart": map[string]string{"id": id}})
	})
	mux.HandleFunc("/api/cart/", func(w http.ResponseWriter, r *http.Request) {
		parts := r.URL.Path[len("/api/cart/"):]
		var id, suffix string
		for _, c := range []string{"/items", "/checkout-token"} {
			if len(parts) >= len(c) && parts[len(parts)-len(c):] == c {
				id = parts[:len(parts)-len(c)]
				suffix = c
				break
			}
		}
		if id == "" {
			http.Error(w, "not found", 404)
			return
		}
		mu.Lock()
		ct, ok := carts[id]
		mu.Unlock()
		if !ok {
			http.Error(w, "cart missing - business_logic_state_error", 400)
			return
		}
		if suffix == "/items" {
			ct.items = append(ct.items, "item")
			json.NewEncoder(w).Encode(map[string]string{"status": "item added"})
			return
		}
		if suffix == "/checkout-token" {
			if len(ct.items) == 0 {
				http.Error(w, "cart empty - need item", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"token": "checkout-" + id})
			return
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		cartID := r.URL.Query().Get("cart_id")
		if cartID == "" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if v, ok := body["cart_id"]; ok {
				cartID = fmt.Sprint(v)
			}
		}
		mu.Lock()
		ct, ok := carts[cartID]
		mu.Unlock()
		if !ok || len(ct.items) == 0 {
			http.Error(w, "cart missing or empty - business_logic_state_error", 400)
			return
		}
		fmt.Fprintln(w, "checkout success")
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:9007", mux))
}
