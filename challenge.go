//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

// NewChallenge creates a new challenge with default parameters.
func NewChallenge() (msg Message) {
	return NewChallengeWithParams(Parameters{})
}

// NewChallengeEncoded creates a new challenge with default parameters and
// encoded for the client.
func NewChallengeEncoded() string {

	// Create a new challenge message.
	msg := NewChallengeWithParams(Parameters{})

	// Return the encoded challenge message.
	return msg.Encode()
}

// NewChallengeWithParams creates a new challenge with the given parameters.
func NewChallengeWithParams(params Parameters) (msg Message) {

	// Populate any missing parameters.
	params.populate()

	// Generate the challenge and signature.
	algo, _ := AlgorithmFromString(params.Algorithm)
	challenge := generateHash(algo, params.Salt, params.Number)
	signature := Sign(algo, challenge)
	msg = Message{
		Algorithm: params.Algorithm,
		Salt:      params.Salt,
		Challenge: challenge,
		Signature: signature,
		// Number is a secret and must not be exposed to the client.
	}

	// Return the challenge message.
	return msg
}
