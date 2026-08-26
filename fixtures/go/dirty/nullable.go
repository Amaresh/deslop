package billing

import "net/http"

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT m.id, m.sender_id, r2.name
		 FROM chat_messages m
		 LEFT JOIN riders r2 ON m.sender_id = r2.id`)
	var id, bikeID2 string
	var senderName string
	for rows.Next() {
		rows.Scan(&id, &bikeID2, &senderName)
	}
	_ = err
}
