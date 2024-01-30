//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"github.com/k42-software/go-altcha/rand"
	"testing"
)

func TestMessageString(t *testing.T) {

	originalMsg := Message{
		Algorithm: "SHA-256",
		Salt:      "0V5xzYiSFmY1swbb",
		Number:    49500,
		Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
		Signature: "-gytD6e0qjPZknud02kOzq8KqsayfXfGI1exZXFjI6k",
	}
	expectedText := `Altcha algorithm=SHA-256, number=49500, salt=0V5xzYiSFmY1swbb, challenge=69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7, signature=-gytD6e0qjPZknud02kOzq8KqsayfXfGI1exZXFjI6k`

	actualText := originalMsg.String()
	if actualText != expectedText {
		t.Errorf("Expected encoded string to be %s, got %s", expectedText, actualText)
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

func TestMessageSolve(t *testing.T) {
	tests := []struct {
		name              string
		message           Message
		maximumComplexity int
		wantNumber        int
		wantOk            bool
	}{
		{
			name: "ValidChallenge",
			message: Message{
				Algorithm: "SHA-256",
				Salt:      "0V5xzYiSFmY1swbb",
				Challenge: "69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7",
			},
			maximumComplexity: DefaultComplexity,
			wantNumber:        49500,
			wantOk:            true,
		},
		{
			name: "UnsolvableChallenge",
			message: Message{
				Algorithm: "SHA-256",
				Salt:      "0V5xzYiSFmY1swbb",
				Challenge: "unsolvableChallengeHash",
			},
			maximumComplexity: DefaultComplexity,
			wantNumber:        -1,
			wantOk:            false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotNumber, gotOk := tc.message.Solve(tc.maximumComplexity)
			if gotNumber != tc.wantNumber || gotOk != tc.wantOk {
				t.Errorf("Message.Solve() = (%v, %v), want (%v, %v)", gotNumber, gotOk, tc.wantNumber, tc.wantOk)
			}
		})
	}
}

func TestSolveChallenge(t *testing.T) {
	tests := []struct {
		name              string
		challenge         string
		maximumComplexity int
		wantResponse      string
		wantOk            bool
	}{
		{
			name:              "ValidChallenge",
			challenge:         `{"algorithm":"SHA-256","salt":"0V5xzYiSFmY1swbb","challenge":"69df4e03d8fffc1d66aeba60384ad28d70caed4bcf10c69f80e0a16666eae6a7"}`,
			maximumComplexity: DefaultComplexity,
			wantResponse:      `eyJhbGdvcml0aG0iOiJTSEEtMjU2Iiwic2FsdCI6IjBWNXh6WWlTRm1ZMXN3YmIiLCJudW1iZXIiOjQ5NTAwLCJjaGFsbGVuZ2UiOiI2OWRmNGUwM2Q4ZmZmYzFkNjZhZWJhNjAzODRhZDI4ZDcwY2FlZDRiY2YxMGM2OWY4MGUwYTE2NjY2ZWFlNmE3Iiwic2lnbmF0dXJlIjoiIn0=`,
			wantOk:            true,
		},
		{
			name:              "InvalidChallenge",
			challenge:         "invalidEncodedChallenge",
			maximumComplexity: DefaultComplexity,
			wantResponse:      "",
			wantOk:            false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotResponse, gotOk := SolveChallenge(tc.challenge, tc.maximumComplexity)
			if gotOk != tc.wantOk || (tc.wantOk && gotResponse != tc.wantResponse) {
				t.Logf("SolveChallenge(%v, %v)", tc.challenge, tc.maximumComplexity)
				t.Logf("got: (%v, %v)", gotResponse, gotOk)
				t.Logf("want: (%v, %v)", tc.wantResponse, tc.wantOk)
				t.Errorf("SolveChallenge did not return expected result")
			}
		})
	}
}
