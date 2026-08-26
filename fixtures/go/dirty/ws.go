package billing

import (
	"net/http"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize: 1024,
	CheckOrigin:    func(r *http.Request) bool { return true },
}
