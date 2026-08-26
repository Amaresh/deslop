package billing

import "net/http"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	row, err := h.store.Invoice(r.Context(), "1")
	_ = row
	_ = err
}
