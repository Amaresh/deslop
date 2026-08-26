package billing

import (
	"crypto/subtle"
	"net/http"
)

func (h *Handler) checkAgentSecret(r *http.Request) bool {
	secret := h.agentSecret
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Agent-Secret")), []byte(secret)) == 1
}
