//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"mime"
	"net/http"
	"net/url"
)

// ParseJSON parses the request body as JSON and stores the result in r.Form.
//
// The request body is capped at 10 MB and parsed as JSON. The parsed values
// are stored in r.Form.
//
// This is a very basic HTTP request body helper. This is probably fine for
// proof of concept and passing just a couple of fields, but if you're handling
// complex JSON structures, you should use a much better solution.
//
// For a more comprehensive solution see;
// https://www.alexedwards.net/blog/how-to-properly-parse-a-json-request-body
func ParseJSON(r *http.Request) error {

	if r.Body == nil {
		return errors.New("request body is empty")
	}

	// Check the content-type is JSON
	header := r.Header.Get("Content-Type")
	// RFC 7231, section 3.1.1.5 - empty type
	//   MAY be treated as application/octet-stream
	if header == "" {
		header = "application/octet-stream"
	}
	ct, _, err := mime.ParseMediaType(header)
	if err != nil {
		return errors.New("invalid Content-Type")
	}
	switch ct {
	case "application/json", "text/json":
	default:
		return errors.New("Content-Type is not application/json")
	}

	// Decode the JSON body into the Form map
	target := make(map[string]interface{})
	decoder := json.NewDecoder(r.Body)
	if err = decoder.Decode(&target); err != nil {
		return errors.Wrap(err, "decoding JSON")
	}

	// Add the values to r.Form
	r.Form = make(url.Values)
	for key, value := range target {
		valueStr, ok := value.(string)
		if !ok {
			valueStr = fmt.Sprintf("%v", value)
		}
		r.Form.Add(key, valueStr)
	}

	return nil
}
