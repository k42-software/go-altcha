//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"github.com/k42-software/go-altcha/rand"
	"testing"
)

func TestMessageIsValidResponse(t *testing.T) {

	randomInt = rand.Int       // Reset randomInt to use the real function
	randomString = rand.String // Reset randomString to use the real function

	// Test with a valid response
	validMsg := Message{
		Algorithm: "SHA-256",
		Salt:      "0V5xzYiSFmY1swbb",
		Number:    49500,
		Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
		Signature: "-gytD6e0qjPZknud02kOzq8KqsayfXfGI1exZXFjI6k",
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
