package billing

import "net/http"

func (h *Handler) checkAgentSecret(r *http.Request) bool {
	secret := h.agentSecret
	return r.Header.Get("X-Agent-Secret") == secret
}
