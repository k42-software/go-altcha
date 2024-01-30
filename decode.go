//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/base64"
	"encoding/json"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"unicode"
)

// DecodeChallenge decodes output from NewChallengeEncoded.
func DecodeChallenge(encoded string) (msg Message, err error) {
	if strings.HasPrefix(encoded, TextPrefix) {
		return DecodeText(encoded)
	}

	return DecodeJSON([]byte(encoded))
}

// DecodeResponse decodes the response Message from the client.
func DecodeResponse(encoded string) (msg Message, err error) {
	if strings.HasPrefix(encoded, TextPrefix) {
		return DecodeText(encoded)
	}

	var jsonBytes []byte
	jsonBytes, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return msg, errors.Wrap(err, "invalid base64 encoding")
	}

	return DecodeJSON(jsonBytes)
}

// DecodeJSON decodes a Message stored in JSON format.
func DecodeJSON(encoded []byte) (msg Message, err error) {
	err = json.Unmarshal(encoded, &msg)
	return msg, errors.Wrap(err, "invalid message")
}

// DecodeText decodes the output from message.String().
func DecodeText(encoded string) (msg Message, err error) {
	if !strings.HasPrefix(encoded, TextPrefix) {
		return msg, errors.New("invalid text encoding of message")
	}

	// Split the input into fields based on commas and whitespace.
	fields := strings.FieldsFunc(encoded[len(TextPrefix):], func(r rune) bool {
		return r == ',' || r == ' ' || unicode.IsSpace(r)
	})

	// Extract the values from the fields.
	for _, field := range fields {
		switch {
		case strings.HasPrefix(field, "algorithm="):
			msg.Algorithm = field[len("algorithm="):]
		case strings.HasPrefix(field, "salt="):
			msg.Salt = field[len("salt="):]
		case strings.HasPrefix(field, "number="):
			msg.Number, err = strconv.Atoi(field[len("number="):])
		case strings.HasPrefix(field, "challenge="):
			msg.Challenge = field[len("challenge="):]
		case strings.HasPrefix(field, "signature="):
			msg.Signature = field[len("signature="):]
		default:
			return Message{}, errors.New("invalid message")
		}
	}

	// Return the Message.
	return msg, nil
}
