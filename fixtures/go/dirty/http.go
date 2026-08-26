package billing

import "net/http"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("https://upstream.example")
	_ = resp
	_ = err
}
