// Package web embeds the compiled single-page UI (web/dist, built with `make ui`).
package web

import "embed"

// Dist holds the built UI. The directory is committed so `go build` works
// without Node.js; rebuild it with `make ui` after changing the frontend.
//
//go:embed all:dist
var Dist embed.FS
