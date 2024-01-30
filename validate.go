//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

// ValidateResponse decodes and validates the response from the client.
func ValidateResponse(encoded string, preventReplay bool) (ok bool) {

	// decode the response
	msg, err := DecodeResponse(encoded)
	if err != nil {
		return false
	}

	// check if the response contains a valid solution to the challenge
	ok = msg.IsValidResponse()
	if !ok {
		return false
	}

	// skip the rest if replay prevention is not enabled
	if !preventReplay {
		return true
	}

	// check if the response is a replay
	// (only do if this it is valid, so someone can't denial-of-service you by
	// sending a bunch of invalid responses with valid signatures)
	if IsSignatureBanned(msg.Signature) {
		return false
	}

	// add the signature to the list of banned signatures
	BanSignature(msg.Signature)

	return true // Success!
}
