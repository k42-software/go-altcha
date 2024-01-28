// @author: Brian Wojtczak
// @copyright: 2024 by Brian Wojtczak
// @license: BSD-style license found in the LICENSE file

package altcha

// NewChallenge creates a new challenge with default parameters.
func NewChallenge() string {
	return NewChallengeWithParams(Parameters{})
}

// NewChallengeWithParams creates a new challenge with the given parameters.
func NewChallengeWithParams(params Parameters) string {

	// Populate any missing parameters.
	params.populate()

	// Generate the challenge and signature.
	algo, _ := AlgorithmFromString(params.Algorithm)
	challenge := generateHash(algo, params.Salt, params.Number)
	signature := Sign(algo, challenge)
	message := Message{
		Algorithm: params.Algorithm,
		Salt:      params.Salt,
		Challenge: challenge,
		Signature: signature,
		// Number is a secret and must not be exposed to the client.
	}

	// Return the encoded challenge message.
	return message.Encode()
}
