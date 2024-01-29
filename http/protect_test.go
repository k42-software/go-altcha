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

	t.Run("HappyPath", func(t *testing.T) {

		// Step 1: Requesting the Challenge
		w := httptest.NewRecorder()
		ok := Protect(w, "") // Call Protect to get the challenge
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
		ok = Protect(w, solvedChallenge)

		if !ok {
			t.Errorf("Expected Protect to return true after sending solved challenge; got false")
		}

	})

	t.Run("InvalidResponse", func(t *testing.T) {

		w := httptest.NewRecorder()
		ok := Protect(w, "invalid-challenge-response")
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

	// Create a valid challenge and response
	challenge := altcha.NewChallenge()
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

	// Create a valid challenge and response
	challenge := altcha.NewChallenge()
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
