package testdata

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var permissiveUpgrader = websocket.Upgrader{
	CheckOrigin:      isValidOrigin,
	HandshakeTimeout: 10 * time.Second,
}

func isValidOrigin(r *http.Request) bool {
	return true
}

func strictOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == "https://app.example.com"
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
}
