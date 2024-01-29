//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
)

// DecodeMessage decodes the response message from the client.
func DecodeMessage(encoded string) (msg Message, err error) {
	var jsonBytes []byte
	jsonBytes, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return msg, errors.Wrap(err, "invalid base64 encoding")
	}
	err = json.Unmarshal(jsonBytes, &msg)
	return msg, errors.Wrap(err, "invalid message")
}
