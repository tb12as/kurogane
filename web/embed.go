// Package web embeds the static Nuxt build (web/.output/public) into the Go binary.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:.output/public
var dist embed.FS

// FS returns the built UI rooted at the public dir.
func FS() fs.FS {
	f, _ := fs.Sub(dist, ".output/public")
	return f
}
