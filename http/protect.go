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
// When the passed in challenge is empty, this function will write a new
// challenge to the response, with a 200 status code, and return false.
//
// When the passed in challenge is not empty, this function will validate the
// response and write a 403 status code if the response is invalid, and return
// false. On successfully validating the challenge, this will return true.
//
// If this function returns false, then a response has been written already,
// and no further action should be taken for the request.
func Protect(w http.ResponseWriter, challenge string, addAuthenticateHeader bool) (ok bool) {

	if len(challenge) == 0 {

		// Create a new challenge
		newChallenge := altcha.NewChallenge()

		// Set the headers
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		if addAuthenticateHeader {
			w.Header().Set("WWW-Authenticate", newChallenge.String())
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write the challenge
		_, _ = w.Write([]byte(newChallenge.Encode()))
		return false
	}

	// Validate the response
	if !altcha.ValidateResponse(challenge, true) {
		http.Error(w, "Invalid altcha response", http.StatusForbidden)
		return false
	}

	// Success!
	return true
}

// ProtectForm protects a request using the altcha challenge.
//
// The request is parsed using r.ParseForm() and the challenge is read from
// r.FormValue("altcha"). This supports passing the challenge information in
// both the body and the URL query string. See r.ParseForm() for more details.
func ProtectForm(protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Look for the altcha response in the form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form data", http.StatusBadRequest)
			return
		}
		challenge := r.FormValue("altcha")

		// Fall back to looking in the Authorization header
		if len(challenge) == 0 {
			challenge = getAuthorizationHeader(r)
		}

		// Run the protection logic
		ok := Protect(w, challenge, true)
		if !ok {
			return
		}

		// Success! Run the protected handler
		protected.ServeHTTP(w, r)
	})
}

// ProtectJSON protects a request using the altcha challenge.
//
// The request body is capped at 10 MB and parsed as JSON. The parsed values
// are stored in r.Form. The challenge is read from r.FormValue("altcha").
func ProtectJSON(protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Limit the size of the request body to 10 MB
		r.Body = http.MaxBytesReader(w, r.Body, 10*1048576)

		// Look for the altcha response in the JSON body
		if err := ParseJSON(r); err != nil {
			http.Error(w, "Error parsing JSON data", http.StatusBadRequest)
			return
		}
		challenge := r.FormValue("altcha")

		// Fall back to looking in the Authorization header
		if len(challenge) == 0 {
			challenge = getAuthorizationHeader(r)
		}

		// Run the protection logic
		ok := Protect(w, challenge, true)
		if !ok {
			return
		}

		// Success! Run the protected handler
		protected.ServeHTTP(w, r)
	})
}

// ProtectHeader protects a request using the altcha challenge passed through
// HTTP headers as defined in the M2M Altcha specification.
//
// This function has slightly different behaviour than the other protect
// functions. This will respond with either a new challenge, using a 401 status
// code, or it runs the protected handler. This does not output 200 or 403
// status codes.
//
// Challenges are placed in the WWW-Authenticate header, in text format.
//
// Responses are expected to be in the Authorization header, in text format.
//
// @see https://altcha.org/docs/m2m-altcha
func ProtectHeader(protected http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Get the response from the Authorization header
		msg, _ := ParseAuthorizationHeader(r)

		// check if the response contains a valid solution to the challenge
		if msg.IsValidResponse() {

			// check if the response is a replay
			// (only do if this it is valid, so someone can't denial-of-service you by
			// sending a bunch of invalid responses with valid signatures)
			if !altcha.IsSignatureBanned(msg.Signature) {

				// add the signature to the list of banned signatures
				altcha.BanSignature(msg.Signature)

				// Success! Run the protected handler
				protected.ServeHTTP(w, r)
				return
			}
		}

		// Failed! Send a new challenge
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		w.Header().Set("WWW-Authenticate", altcha.NewChallenge().String())
		w.WriteHeader(http.StatusUnauthorized)
		return
	})
}
