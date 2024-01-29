//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

// DecodeChallenge decodes output from NewChallenge.
func DecodeChallenge(encoded string) (msg Message, err error) {
	err = json.Unmarshal([]byte(encoded), &msg)
	return msg, errors.Wrap(err, "invalid message")
}

// DecodeResponse decodes the response message from the client.
func DecodeResponse(encoded string) (msg Message, err error) {
	var jsonBytes []byte
	jsonBytes, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return msg, errors.Wrap(err, "invalid base64 encoding")
	}
	err = json.Unmarshal(jsonBytes, &msg)
	return msg, errors.Wrap(err, "invalid message")
}
