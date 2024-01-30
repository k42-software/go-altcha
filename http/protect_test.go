//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"bytes"
	"encoding/json"
	"github.com/k42-software/go-altcha"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtect(t *testing.T) {

	// Rotate the secrets so that we get a clean slate for testing
	altcha.RotateSecrets()
	altcha.RotateSecrets()
	altcha.RotateSecrets()

	t.Run("HappyPath", func(t *testing.T) {

		// Step 1: Requesting the Challenge
		w := httptest.NewRecorder()
		ok := Protect(w, "", true) // Call Protect to get the challenge
		if ok {
			t.Errorf("Expected Protect to return false when no challenge is provided; got true")
		}

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200 OK; got %v", resp.StatusCode)
		}

		// Read the challenge from the response body
		body, _ := io.ReadAll(resp.Body)
		challenge := string(body)

		// Step 2: Solving the Challenge
		solvedChallenge, ok := altcha.SolveChallenge(challenge, altcha.DefaultComplexity)
		if !ok {
			t.Fatalf("Failed to solve challenge")
		}

		// Step 3: Sending the Solved Challenge Response
		w = httptest.NewRecorder()
		ok = Protect(w, solvedChallenge, true)

		if !ok {
			t.Errorf("Expected Protect to return true after sending solved challenge; got false")
		}

	})

	t.Run("InvalidResponse", func(t *testing.T) {

		w := httptest.NewRecorder()
		ok := Protect(w, "invalid-challenge-response", true)
		if ok {
			t.Errorf("Expected Protect to return false when invalid challenge is provided; got true")
		}

		resp := w.Result()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Expected status 403 Forbidden; got %v", resp.StatusCode)
		}

	})

}

func TestProtectForm(t *testing.T) {

	// Rotate the secrets so that we get a clean slate for testing
	altcha.RotateSecrets()
	altcha.RotateSecrets()
	altcha.RotateSecrets()

	// Create a valid challenge and response
	challenge := altcha.NewChallengeEncoded()
	response, ok := altcha.SolveChallenge(challenge, altcha.DefaultComplexity)
	if !ok {
		t.Fatalf("could not solve challenge: %v", challenge)
	}

	// Mock HTTP handler
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // Indicate a successful handling
	})

	// Create test server using ProtectForm
	testServer := httptest.NewServer(ProtectForm(mockHandler))
	defer testServer.Close()

	// Test cases
	tests := []struct {
		name       string
		form       string
		wantStatus int
	}{
		{
			name:       "ValidChallenge",
			form:       "altcha=" + response,
			wantStatus: http.StatusOK,
		},
		{
			name:       "InvalidChallenge",
			form:       "altcha=invalid-challenge",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// Create a request with form data
			req, err := http.NewRequest("POST", testServer.URL, strings.NewReader(tc.form))
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Perform the request
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("could not send request: %v", err)
			}

			// Assert the status code
			if response.StatusCode != tc.wantStatus {
				t.Errorf("expected status %v; got %v", tc.wantStatus, response.StatusCode)
			}

		})
	}
}

func TestProtectJSON(t *testing.T) {

	// Rotate the secrets so that we get a clean slate for testing
	altcha.RotateSecrets()
	altcha.RotateSecrets()
	altcha.RotateSecrets()

	// Create a valid challenge and response
	challenge := altcha.NewChallengeEncoded()
	response, ok := altcha.SolveChallenge(challenge, altcha.DefaultComplexity)
	if !ok {
		t.Fatalf("could not solve challenge: %v", challenge)
	}

	// Mock HTTP handler
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // Indicate a successful handling
	})

	// Create test server using ProtectJSON
	testServer := httptest.NewServer(ProtectJSON(mockHandler))
	defer testServer.Close()

	// Test cases
	tests := []struct {
		name       string
		jsonData   map[string]string
		wantStatus int
	}{
		{
			name:       "ValidChallenge",
			jsonData:   map[string]string{"altcha": response},
			wantStatus: http.StatusOK,
		},
		{
			name:       "InvalidChallenge",
			jsonData:   map[string]string{"altcha": "invalid-challenge"},
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Convert jsonData to JSON
			jsonBytes, err := json.Marshal(tc.jsonData)
			if err != nil {
				t.Fatalf("could not marshal json: %v", err)
			}

			// Create a request with JSON data
			req, err := http.NewRequest("POST", testServer.URL, bytes.NewBuffer(jsonBytes))
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// Perform the request
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("could not send request: %v", err)
			}

			// Assert the status code
			if response.StatusCode != tc.wantStatus {
				t.Errorf("expected status %v; got %v", tc.wantStatus, response.StatusCode)
			}
		})
	}
}

func TestProtectHeader(t *testing.T) {

	// Rotate the secrets for a clean slate
	altcha.RotateSecrets()
	altcha.RotateSecrets()
	altcha.RotateSecrets()

	// Create a valid challenge and response
	msg := altcha.NewChallenge()
	var ok bool
	msg.Number, ok = msg.Solve(altcha.DefaultComplexity)
	if !ok {
		t.Fatalf("could not solve challenge: %v", msg.String())
	}
	response := msg.String()

	// Mock HTTP handler
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // Indicate successful handling
	})

	// Create test server using ProtectHeader
	testServer := httptest.NewServer(ProtectHeader(mockHandler))
	defer testServer.Close()

	// Test cases
	tests := []struct {
		name            string
		header          string
		wantStatus      int
		expectChallenge bool // Expect a WWW-Authenticate header in response
	}{
		{
			name:            "ValidChallenge",
			header:          response,
			wantStatus:      http.StatusOK,
			expectChallenge: false,
		},
		{
			name:            "InvalidChallenge",
			header:          "invalid-challenge",
			wantStatus:      http.StatusUnauthorized,
			expectChallenge: true,
		},
		{
			name:            "NoChallenge",
			header:          "",
			wantStatus:      http.StatusUnauthorized,
			expectChallenge: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			// Create a request
			req, err := http.NewRequest("GET", testServer.URL, nil)
			if err != nil {
				t.Fatalf("could not create request: %v", err)
			}
			if tc.header != "" {
				t.Logf("Authorization: %s", tc.header)
				req.Header.Set("Authorization", tc.header)
			}

			// Perform the request
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("could not send request: %v", err)
			}

			// Assert the status code
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("expected status %v; got %v", tc.wantStatus, resp.StatusCode)
			}

			// Check for WWW-Authenticate header
			if tc.expectChallenge {
				if resp.Header.Get("WWW-Authenticate") == "" {
					t.Error("expected WWW-Authenticate header, but not found")
				}
			} else {
				if resp.Header.Get("WWW-Authenticate") != "" {
					t.Error("did not expect WWW-Authenticate header, but found one")
				}
			}

		})
	}
}
