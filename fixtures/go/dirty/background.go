package billing

import (
	"context"
	"net/http"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go work(context.Background())
}
