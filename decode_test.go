//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"testing"
)

func TestDecodeChallenge(t *testing.T) {

	// Test case for invalid JSON format
	invalidJSON := "invalid-json"
	if _, err := DecodeChallenge(invalidJSON); err == nil {
		t.Error("Expected error for invalid json, got nil")
	}

	// Test case for successful decoding
	validJSON := `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7","signature":"fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9"}`
	msg, err := DecodeChallenge(validJSON)
	if err != nil {
		t.Errorf("DecodeChallenge failed: %v", err)
	}

	// Verify the contents of msg
	expectedAlgorithm := "SHA-256"
	expectedSalt := "0V5xzYiSFmY1swbb"
	expectedChallenge := "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7"
	expectedSignature := "fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9"

	if msg.Algorithm != expectedAlgorithm {
		t.Errorf("Expected Algorithm to be %s, got %s", expectedAlgorithm, msg.Algorithm)
	}
	if msg.Salt != expectedSalt {
		t.Errorf("Expected Salt to be %s, got %s", expectedSalt, msg.Salt)
	}
	if msg.Challenge != expectedChallenge {
		t.Errorf("Expected Challenge to be %s, got %s", expectedChallenge, msg.Challenge)
	}
	if msg.Signature != expectedSignature {
		t.Errorf("Expected Signature to be %s, got %s", expectedSignature, msg.Signature)
	}
}

func TestDecodeResponse(t *testing.T) {

	// Test case for invalid base64 encoding
	invalidBase64 := "invalid-base64"
	if _, err := DecodeResponse(invalidBase64); err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}

	// Test case for invalid JSON format
	validBase64InvalidJson := base64.StdEncoding.EncodeToString([]byte("invalid-json"))
	if _, err := DecodeResponse(validBase64InvalidJson); err == nil {
		t.Error("Expected error for invalid json, got nil")
	}

	// Test case for successful decoding
	encoded := "eyJhbGdvcml0aG0iOiJTSEEtMjU2Iiwic2FsdCI6IjBWNXh6WWlTRm1ZMXN3YmIiLCJjaGFsbGVuZ2UiOiI2OWRmNGUwM2Q4ZmZmYzFkNjZhZWJhNjAzODRhZDI4ZDcwY2FlZDRiY2YxMGM2OWY4MGUwYTE2NjY2ZWFlNmE3Iiwic2lnbmF0dXJlIjoiZmEwY2FkMGZhN2I0YWEzM2Q5OTI3YjlkZDM2OTBlY2VhZjBhYWFjNmIyN2Q3N2M2MjM1N2IxNjU3MTYzMjNhOSJ9"
	msg, err := DecodeResponse(encoded)
	if err != nil {
		t.Errorf("DecodeResponse failed: %v", err)
	}

	// Verify the contents of msg
	expectedAlgorithm := "SHA-256"
	expectedSalt := "0V5xzYiSFmY1swbb"
	expectedChallenge := "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7"
	expectedSignature := "fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9"

	if msg.Algorithm != expectedAlgorithm {
		t.Errorf("Expected Algorithm to be %s, got %s", expectedAlgorithm, msg.Algorithm)
	}
	if msg.Salt != expectedSalt {
		t.Errorf("Expected Salt to be %s, got %s", expectedSalt, msg.Salt)
	}
	if msg.Challenge != expectedChallenge {
		t.Errorf("Expected Challenge to be %s, got %s", expectedChallenge, msg.Challenge)
	}
	if msg.Signature != expectedSignature {
		t.Errorf("Expected Signature to be %s, got %s", expectedSignature, msg.Signature)
	}

}
