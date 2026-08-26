package testdata

import (
	"net/http"
)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	go h.audit(r.Context())
	go h.orphan()
	go func() {
		<-r.Context().Done()
	}()
	go work(ctx)
}

func worker() {
	go background()
}
