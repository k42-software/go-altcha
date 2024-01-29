//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"crypto/hmac"
	"encoding/base64"
	"hash"
)

// Sign generates a signature for the given text.
func Sign(algo Algorithm, text string) string {
	secret, _ := GetSecrets()
	return sign(algo, text, secret)
}

func sign(algo Algorithm, text, secret string) string {
	if len(secret) == 0 {
		panic("secret not provided to signing function")
	}
	newHasher := func() (hasher hash.Hash) {
		hasher, _ = getHasher(algo)
		return hasher
	}
	signer := hmac.New(newHasher, []byte(secret))
	signer.Write([]byte(text))

	// The official server implementation example uses hex encoding.
	// However, as the client doesn't read the signature, this can be changed
	// without affecting compatibility.
	// This implementation uses base64 encoding produces shorter signatures.
	return base64.RawURLEncoding.EncodeToString(signer.Sum(nil))
}

// VerifySignature checks if the given signature is valid for the given text.
func VerifySignature(algo Algorithm, text string, signature string) (valid bool) {
	if len(signature) == 0 {
		return false
	}
	current, previous := GetSecrets()
	return signature == sign(algo, text, current) || signature == sign(algo, text, previous)
}
