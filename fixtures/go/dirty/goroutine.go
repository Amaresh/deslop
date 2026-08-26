package billing

import (
	"net/http"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go h.audit()
}
