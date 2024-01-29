//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseJSON(t *testing.T) {
	tests := []struct {
		name          string
		requestBody   string
		contentType   string
		expectedError error
	}{
		{
			name:          "ValidJSON",
			requestBody:   `{"key": "value", "num": 342}`,
			contentType:   "application/json",
			expectedError: nil,
		},
		{
			name:          "InvalidJSON",
			requestBody:   `{"key": ...`,
			contentType:   "application/json",
			expectedError: errors.New("decoding JSON"), // Simplified error message for illustration
		},
		{
			name:          "InvalidContentType",
			requestBody:   `{}`,
			contentType:   "invalid/mime/type/here",
			expectedError: errors.New("invalid Content-Type"),
		},
		{
			name:          "IncorrectContentType",
			requestBody:   `{}`,
			contentType:   "text/plain",
			expectedError: errors.New("Content-Type is not application/json"),
		},
		{
			name:          "NoContentType",
			requestBody:   `{}`,
			contentType:   "",
			expectedError: errors.New("Content-Type is not application/json"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", bytes.NewBufferString(tc.requestBody))
			req.Header.Add("Content-Type", tc.contentType)

			err := ParseJSON(req)

			// Check if the error matches the expected error
			if (err != nil) != (tc.expectedError != nil) || (err != nil && !strings.Contains(err.Error(), tc.expectedError.Error())) {
				t.Errorf("ParseJSON() error = %v, wantErr %v", err, tc.expectedError)
			}
		})
	}
}
