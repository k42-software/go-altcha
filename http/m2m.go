//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"github.com/k42-software/go-altcha"
	"net/http"
	"strings"
)

// ParseAuthorizationHeader parses an Altcha response from an Authorization header.
func ParseAuthorizationHeader(r *http.Request) (msg altcha.Message, ok bool) {
	msg, _ = altcha.DecodeText(getAuthorizationHeader(r))
	ok = msg.Signature != "" // We assume that we decoded OK if we have a signature
	return msg, ok
}

func getAuthorizationHeader(r *http.Request) (response string) {
	response = r.Header.Get("Authorization")
	if strings.HasPrefix(response, altcha.TextPrefix) {
		return response
	}
	return ""
}
