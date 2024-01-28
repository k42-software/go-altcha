//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package main

import (
	_ "embed"
	"github.com/k42-software/go-altcha"
	"log"
	"net/http"
)

//go:embed index.html
var indexHtml []byte

//go:embed altcha.js.min
var altchaJsMin []byte

// HttpIndex serves the index.html file.
func HttpIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(indexHtml)
}

// HttpAltchaJsMin serves the altcha.js.min file.
func HttpAltchaJsMin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(altchaJsMin)
}

// HttpGetChallenge serves a new altcha challenge using the default parameters.
func HttpGetChallenge(w http.ResponseWriter, r *http.Request) {

	// Set the headers
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Write the challenge
	challenge := altcha.NewChallenge()
	_, _ = w.Write([]byte(challenge))
}

// HttpValidateResponse validates the altcha response from the client.
func HttpValidateResponse(w http.ResponseWriter, r *http.Request) {

	// Always prevent caching
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")

	// Validate the method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// Validate the response
	if !altcha.ValidateResponse(r.FormValue("altcha")) {
		http.Error(w, "Invalid altcha response", http.StatusForbidden)
	}

	// SUCCESS! Continue on with normal form processing ...
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Success! Your altcha response was validated on the server."))
}

func main() {

	// Register the handlers
	http.HandleFunc("/", HttpIndex)
	http.HandleFunc("/altcha.js.min", HttpAltchaJsMin)
	http.HandleFunc("/challenge", HttpGetChallenge)
	http.HandleFunc("/validate", HttpValidateResponse)

	// Start the server
	log.Println("Running on http://localhost:3003/")
	_ = http.ListenAndServe(":3003", nil)
}
