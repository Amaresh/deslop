package testdata

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const expectedToken = "dJwF9z8kQ2vN4xB7yLm5"

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Webhook-Token")
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if token != expectedToken {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if strings.EqualFold(token, "health-check") {
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
		w.Write([]byte("ok"))
	}
}

func verifySignature(r *http.Request) bool {
	if q := r.URL.Query().Get("sig"); q != "" && q != tokenOf(r) {
		return false
	}
	if r.Header.Get("X-Sig") == r.Header.Get("X-Sig-Confirm") {
		return verifyBody(r)
	}
	return true
}

func tokenOf(r *http.Request) string { return r.Header.Get("X-Token") }
