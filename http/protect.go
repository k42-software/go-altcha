//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"github.com/k42-software/go-altcha"
	"net/http"
)

// Protect protects a request using the altcha challenge.
//
// You must parse the request and pass the challenge string to this function.
//
// This function returns true when the challenge has been passed successfully.
// If this function returns false, then a response has been written already,
// and no further action should be taken for the request.
func Protect(w http.ResponseWriter, challenge string) (ok bool) {

	if len(challenge) == 0 {
		// Set the headers
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write the challenge
		_, _ = w.Write([]byte(altcha.NewChallenge()))
		return false
	}

	// Validate the response
	if !altcha.ValidateResponse(challenge) {
		http.Error(w, "Invalid altcha response", http.StatusForbidden)
		return false
	}

	return true
}

// ProtectForm protects a request using the altcha challenge.
//
// The request is parsed using r.ParseForm() and the challenge is read from
// r.FormValue("altcha"). This supports passing the challenge information in
// both the body and the URL query string. See r.ParseForm() for more details.
func ProtectForm(protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		challenge := r.FormValue("altcha")

		ok := Protect(w, challenge)
		if !ok {
			return
		}

		protected.ServeHTTP(w, r)
	})
}

// ProtectJSON protects a request using the altcha challenge.
//
// The request body is capped at 10 MB and parsed as JSON. The parsed values
// are stored in r.Form. The challenge is read from r.FormValue("altcha").
func ProtectJSON(protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		r.Body = http.MaxBytesReader(w, r.Body, 10*1048576)

		if err := ParseJSON(r); err != nil {
			http.Error(w, "Error parsing JSON data", http.StatusBadRequest)
			return
		}
		challenge := r.FormValue("altcha")

		ok := Protect(w, challenge)
		if !ok {
			return
		}

		protected.ServeHTTP(w, r)
	})
}
