//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import "testing"

func TestParametersPopulate(t *testing.T) {
	params := Parameters{}

	params.populate()

	if params.Algorithm != "SHA-256" {
		t.Errorf("Expected default algorithm SHA-256, got %s", params.Algorithm)
	}

	if len(params.Salt) < 10 {
		t.Errorf("Expected salt to be at least 10 characters, got %s", params.Salt)
	}

	if params.Complexity != DefaultComplexity {
		t.Errorf("Expected default complexity %d, got %d", DefaultComplexity, params.Complexity)
	}

	if params.Number <= 0 || params.Number < MinimumComplexity || params.Number > params.Complexity {
		t.Errorf("Number is not in the expected range: got %d", params.Number)
	}
}
