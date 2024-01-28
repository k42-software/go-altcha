//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

// ValidateResponse decodes and validates the response from the client.
func ValidateResponse(encoded string) bool {
	msg, err := DecodeMessage(encoded)
	if err != nil {
		return false
	}
	return msg.IsValidResponse()
}
