//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"github.com/k42-software/go-altcha/rand"
	"testing"
)

func TestDecodeMessage(t *testing.T) {

	// Test case for invalid base64 encoding
	invalidBase64 := "invalid-base64"
	if _, err := DecodeMessage(invalidBase64); err == nil {
		t.Error("Expected error for invalid base64, got nil")
	}

	// Test case for invalid JSON format
	validBase64InvalidJson := base64.StdEncoding.EncodeToString([]byte("invalid-json"))
	if _, err := DecodeMessage(validBase64InvalidJson); err == nil {
		t.Error("Expected error for invalid json, got nil")
	}

	// Test case for successful decoding
	encoded := "eyJhbGdvcml0aG0iOiJTSEEtMjU2Iiwic2FsdCI6IjBWNXh6WWlTRm1ZMXN3YmIiLCJjaGFsbGVuZ2UiOiI2OWRmNGUwM2Q4ZmZmYzFkNjZhZWJhNjAzODRhZDI4ZDcwY2FlZDRiY2YxMGM2OWY4MGUwYTE2NjY2ZWFlNmE3Iiwic2lnbmF0dXJlIjoiZmEwY2FkMGZhN2I0YWEzM2Q5OTI3YjlkZDM2OTBlY2VhZjBhYWFjNmIyN2Q3N2M2MjM1N2IxNjU3MTYzMjNhOSJ9"
	msg, err := DecodeMessage(encoded)
	if err != nil {
		t.Errorf("DecodeMessage failed: %v", err)
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

func TestMessageIsValidResponse(t *testing.T) {

	randomInt = rand.Int       // Reset randomInt to use the real function
	randomString = rand.String // Reset randomString to use the real function

	// Test with a valid response
	validMsg := Message{
		Algorithm: "SHA-256",
		Salt:      "0V5xzYiSFmY1swbb",
		Number:    49500,
		Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
		Signature: "fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9",
	}
	if !validMsg.IsValidResponse() {
		t.Error("Expected valid response to be true, got false")
	}

	// Test with invalid algorithm
	invalidAlgoMsg := validMsg
	invalidAlgoMsg.Algorithm = "InvalidAlgorithm"
	if invalidAlgoMsg.IsValidResponse() {
		t.Error("Expected response with invalid algorithm to be false, got true")
	}

	// Test with invalid number
	invalidNumberMsg := validMsg
	invalidNumberMsg.Number = -1
	if invalidNumberMsg.IsValidResponse() {
		t.Error("Expected response with invalid number to be false, got true")
	}

	// Test with an invalid challenge
	invalidChallengeMsg := validMsg
	invalidChallengeMsg.Challenge = "incorrect_challenge"
	if invalidChallengeMsg.IsValidResponse() {
		t.Error("Expected response with invalid challenge to be false, got true")
	}

	// Test with invalid signature
	invalidSignatureMsg := validMsg
	invalidSignatureMsg.Signature = "incorrect_signature"
	if invalidSignatureMsg.IsValidResponse() {
		t.Error("Expected response with invalid signature to be false, got true")
	}
}
