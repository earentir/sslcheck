package server

import "embed"

//go:embed webui/*
var webUI embed.FS

// WebUIFS returns the embedded static files for the web UI.
func WebUIFS() embed.FS {
	return webUI
}
