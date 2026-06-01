package server

import (
	"net/http"
	"time"
)

// ListenAndServe starts the HTTP server with timeouts suited to long-running scans.
func ListenAndServe(addr string, handler http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // scans may run many minutes; do not cut off the response
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}
