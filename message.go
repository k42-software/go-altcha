//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// TextPrefix is the prefix used for the text encoding of the message.
const TextPrefix = "Altcha "

// Message represents the messages between the client and server.
type Message struct {

	// Algorithm is the hashing algorithm used to generate the challenge.
	// Supported algorithms are SHA-256, SHA-384, and SHA-512.
	Algorithm string `json:"algorithm"`

	// Salt is a random string used to generate the challenge.
	// The minimum length is 10 characters.
	Salt string `json:"salt"`

	// Number is the secret number which the client must solve for.
	Number int `json:"number,omitempty"`

	// Challenge is the hash which the client must solve for.
	// The minimum length is 40 characters.
	Challenge string `json:"challenge"`

	// Signature is the signature of the challenge.
	Signature string `json:"signature"`
}

// Encode returns the message ready to be sent to the client. The client is
// expecting the message in raw JSON format.
func (message Message) Encode() string {
	// It seems strange that we don't need to base64 encode the jsonBytes here,
	// but the client expects the JSON without the additional encoding.

	jsonBytes, _ := json.Marshal(message)
	return string(jsonBytes)
}

// EncodeWithBase64 returns the message ready to be sent back to the server.
// The server is expecting the message to be JSON wrapped in base64 encoding.
func (message Message) EncodeWithBase64() string {
	jsonBytes, _ := json.Marshal(message)
	return base64.StdEncoding.EncodeToString(jsonBytes)
}

// String returns a textual representation of the message in the format defined
// in the M2M Altcha specification. It is used for both server and client.
// @see https://altcha.org/docs/m2m-altcha
func (message Message) String() string {

	sb := &strings.Builder{}
	sb.WriteString(TextPrefix)

	sb.WriteString("algorithm=")
	sb.WriteString(message.Algorithm)

	if message.Number > 0 {
		sb.WriteString(", number=")
		sb.WriteString(strconv.Itoa(message.Number))
	}

	sb.WriteString(", salt=")
	sb.WriteString(message.Salt) // Must not contain whitespace or commas

	sb.WriteString(", challenge=")
	sb.WriteString(message.Challenge) // hex encoded

	sb.WriteString(", signature=")
	sb.WriteString(message.Signature) // base64 encoded

	return sb.String()
}

// IsValidResponse is used to validate a decoded response from the client.
func (message Message) IsValidResponse() bool {
	algo, ok := AlgorithmFromString(message.Algorithm)
	if !ok {
		return false
	}

	if message.Number <= 0 {
		return false
	}

	if message.Challenge != generateHash(algo, message.Salt, message.Number) {
		return false
	}

	return VerifySignature(algo, message.Challenge, message.Signature)
}

// Solve attempts to solve the challenge within the given maximum complexity.
func (message Message) Solve(maximumComplexity int) (number int, ok bool) {
	if maximumComplexity <= 0 {
		maximumComplexity = DefaultComplexity * 2
	}

	algo, ok := AlgorithmFromString(message.Algorithm)
	if !ok {
		return -1, false
	}

	for i := 1; i <= maximumComplexity; i++ {
		if message.Challenge == generateHash(algo, message.Salt, i) {
			return i, true
		}
	}

	return -1, false
}

// SolveChallenge is a convenience function which decodes the challenge, solves
// it, and returns the response.
func SolveChallenge(challenge string, maximumComplexity int) (response string, ok bool) {

	// Decode the challenge from NewChallengeEncoded()
	msg, err := DecodeChallenge(challenge)
	if err != nil {
		return response, false
	}

	// SolveChallenge the challenge
	msg.Number, ok = msg.Solve(maximumComplexity)

	if ok {
		// Encode the response
		response = msg.EncodeWithBase64()
	}

	return response, ok
}
