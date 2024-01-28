//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

// MinimumComplexity is the minimum complexity allowed.
// @see https://altcha.org/docs/complexity
const MinimumComplexity = 1000

// DefaultComplexity is the default complexity used. This should be increased
// to make the challenge harder to solve.
// @see https://altcha.org/docs/complexity
const DefaultComplexity = 100000

// Parameters are the parameters used to generate a challenge. If any of the
// parameters are missing, they will be generated.
type Parameters struct {

	// Algorithm is the hashing algorithm used to generate the challenge.
	// Supported algorithms are SHA-256, SHA-384, and SHA-512.
	Algorithm string `json:"algorithm"`

	// Salt is a random string used to generate the challenge.
	// The minimum length is 10 characters.
	Salt string `json:"salt"`

	// Complexity is the number of iterations used to generate the challenge.
	// This is only considered when Number is not provided.
	Complexity int `json:"complexity,omitempty"`

	// Number is the secret number which the client must solve for.
	Number int `json:"number,omitempty"`
}

// Populate generates any missing parameters.
func (params *Parameters) populate() {

	// Without an algorithm, we use SHA-256.
	algo, ok := AlgorithmFromString(params.Algorithm)
	if !ok {
		algo = SHA256
		params.Algorithm = algo.String()
	}

	// Without salt, we generate a new one.
	if len(params.Salt) < 10 {
		params.Salt = randomString(16)
	}

	// Without a number, we use the complexity to generate a new one.
	if params.Number <= 0 {
		if params.Complexity <= MinimumComplexity {
			params.Complexity = DefaultComplexity
		}
		params.Number = randomInt(MinimumComplexity, params.Complexity)
	}

}
