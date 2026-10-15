// Package web holds the compiled UI. The build embeds whatever is in dist, so
// the binary is self-contained; `make web` fills it in.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// FS returns the UI rooted at the dist directory.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// dist is embedded at compile time; a failure here is a build error.
		panic("web: embed is missing dist: " + err.Error())
	}
	return sub
}
