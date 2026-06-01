package server

import (
	"io/fs"
	"net/http"
	"strings"
)

func newAPIMux() *http.ServeMux {
	m := http.NewServeMux()
	registerAPI(m)
	return m
}

// APIOnly returns a handler that serves only /api/v1/* .
func APIOnly() http.Handler {
	return newAPIMux()
}

// Web returns a handler: /api/v1/* → API; everything else → static files.
func Web(static fs.FS) http.Handler {
	api := newAPIMux()
	// Embedded paths are webui/index.html — strip prefix so FileServer root is the UI folder.
	sub, err := fs.Sub(static, "webui")
	if err != nil {
		sub = static
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			api.ServeHTTP(w, r)
			return
		}
		// Do not redirect / → /index.html: http.FileServer redirects /index.html → /, causing ERR_TOO_MANY_REDIRECTS.
		if r.URL.Path == "/" || r.URL.Path == "" {
			http.ServeFileFS(w, r, sub, "index.html")
			return
		}
		files.ServeHTTP(w, r)
	})
}

func registerAPI(m *http.ServeMux) {
	m.HandleFunc("/api/v1/health", HandleHealth)
	m.HandleFunc("/api/v1/schema", HandleSchema)
	m.HandleFunc("GET /api/v1/checks", HandleChecksList)
	m.HandleFunc("GET /api/v1/checks/{code}", HandleCheckGet)
	m.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			HandleScanGET(w, r)
		case http.MethodPost:
			HandleScanPOST(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
