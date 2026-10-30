// Package web embeds the built dashboard (bun run build writes dist/app).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UI is the built dashboard, rooted at index.html. Empty until built.
func UI() fs.FS {
	sub, _ := fs.Sub(dist, "dist/app")
	return sub
}
