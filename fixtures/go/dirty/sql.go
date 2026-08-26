package billing

import "net/http"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT id FROM rides WHERE rider_id = $1`, riderID)
	_ = rows
	_ = err
}
