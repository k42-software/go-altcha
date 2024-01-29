//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package main

import (
	"embed"
	"github.com/k42-software/go-altcha/http" // altcha
	"log"
	"net/http"
)

//go:embed index.html
//go:embed protected.html
var files embed.FS

var fileServer = http.FileServer(http.FS(files))

// Simple middleware to browser disable caching
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func main() {

	// Serve the javascript file, which contains the altcha code.
	http.HandleFunc("/altcha.js", altcha.ServeJavascript)
	http.HandleFunc("/altcha.js.license", altcha.ServeJavascript)
	http.HandleFunc("/altcha.min.js", altcha.ServeJavascript)
	http.HandleFunc("/altcha.min.js.license", altcha.ServeJavascript)

	// Serve the protected file, but only if they get the challenge correct!
	http.Handle(
		"/protected.html",

		// This middleware protects the request
		altcha.ProtectForm(

			// This is only run for successful requests.
			fileServer,
		),
	)

	// Serve the index file, which contains the HTML form.
	http.Handle("/", fileServer)

	// Start the server
	log.Println("Running on http://localhost:3003/")
	log.Println(http.ListenAndServe(":3003", noCache(http.DefaultServeMux)))
}
