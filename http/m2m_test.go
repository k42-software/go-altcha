//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"github.com/k42-software/go-altcha"
	"net/http/httptest"
	"testing"
)

func TestParseAuthorizationHeader(t *testing.T) {

	t.Run("Valid", func(t *testing.T) {

		// Create a sample message
		msg := altcha.Message{
			Algorithm: "SHA-256",
			Salt:      "0V5xzYiSFmY1swbb",
			Number:    49500,
			Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
			Signature: "-gytD6e0qjPZknud02kOzq8KqsayfXfGI1exZXFjI6k",
		}

		// Encode the message to a string
		encodedMsg := msg.String()

		// Create a mock HTTP request with the encoded message in the Authorization header
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Add("Authorization", encodedMsg)

		// Test parsing the header
		parsedMsg, ok := ParseAuthorizationHeader(req)

		if !ok {
			t.Errorf("ParseAuthorizationHeader returned false, expected true")
		}

		if parsedMsg.Signature != msg.Signature {
			t.Errorf("Parsed message signature does not match. Expected: %s, Got: %s", msg.Signature, parsedMsg.Signature)
		}
	})

	t.Run("Invalid", func(t *testing.T) {

		// Create a mock HTTP request with an invalid Authorization header
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Add("Authorization", "InvalidHeader")

		// Test parsing the header
		_, ok := ParseAuthorizationHeader(req)

		if ok {
			t.Errorf("ParseAuthorizationHeader returned true for an invalid header, expected false")
		}

	})

}
