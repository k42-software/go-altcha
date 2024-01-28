// @author: Brian Wojtczak
// @copyright: 2024 by Brian Wojtczak
// @license: BSD-style license found in the LICENSE file

package rand

import (
	"testing"
)

func TestIntRangeValidity(t *testing.T) {
	minimum, maximum := 5, 10
	for i := 0; i < 1000; i++ {
		result := Int(minimum, maximum)
		if result < minimum || result >= maximum {
			t.Errorf("Generated number %d is outside the range [%d, %d)", result, minimum, maximum)
		}
	}
}

func TestIntEdgeCases(t *testing.T) {
	testCases := []struct {
		min, max int
		valid    bool
	}{
		{5, 5, false},
		{10, 5, false},
		{-10, -5, true},
		{0, 10000, true},
	}

	for _, tc := range testCases {
		if tc.valid {
			result := Int(tc.min, tc.max)
			if result < tc.min || result >= tc.max {
				t.Errorf("Edge case failed: Generated number %d is outside the range [%d, %d)", result, tc.min, tc.max)
			}
		} else {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Edge case failed: Expected panic for range [%d, %d)", tc.min, tc.max)
				}
			}()
			_ = Int(tc.min, tc.max)
		}
	}
}

// Additional tests for specific error scenarios and distribution can be added as needed
