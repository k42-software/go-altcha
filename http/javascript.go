//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"embed"
	"net/http"
	"path"
	"strings"
)

//go:embed altcha.js
//go:embed altcha.js.license.txt
//go:embed altcha.min.js
var files embed.FS

var fileServer = http.FileServer(http.FS(files))

// ServeJavascript serves the ALTCHA version 0.1.5 javascript files.
//
// This is the same as the code available from:
// - https://cdn.jsdelivr.net/npm/altcha@0.1.5/dist/altcha.js
// - https://github.com/altcha-org/altcha/blob/0.1.5/dist/altcha.js
//
// These files are subject to the ALTCHA license. See altcha.js.license.txt
func ServeJavascript(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(strings.ToLower(r.URL.Path), ".license") {
		r.URL.Path = "/altcha.js.license.txt"
	}
	http.StripPrefix(path.Dir(r.URL.Path), fileServer).ServeHTTP(w, r)
}
