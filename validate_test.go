//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"testing"
)

func TestValidateChallenge(t *testing.T) {
	// Test with a valid encoded message
	validMsg := Message{
		Algorithm: "SHA-256",
		Salt:      "0V5xzYiSFmY1swbb",
		Number:    49500,
		Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
		Signature: "fa0cad0fa7b4aa33d9927b9dd3690eceaf0aaac6b27d77c62357b165716323a9",
	}
	validEncodedMsg := validMsg.EncodeWithBase64()
	if ValidateResponse(validEncodedMsg) {
		t.Error("Expected valid encoded message to return true, got false")
	}

	// Test with invalid encoded string
	invalidEncoded := "invalid-base64"
	if ValidateResponse(invalidEncoded) {
		t.Error("Expected invalid encoded string to return false, got true")
	}

	// Test with a message which has valid encoding but invalid values
	invalidMsg := validMsg
	invalidMsg.Signature = "incorrect_signature" // Invalidate the message
	invalidEncodedMsg := invalidMsg.EncodeWithBase64()
	if ValidateResponse(invalidEncodedMsg) {
		t.Error("Expected valid encoded but invalid message to return false, got true")
	}
}
