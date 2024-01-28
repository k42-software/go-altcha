// @author: Brian Wojtczak
// @copyright: 2024 by Brian Wojtczak
// @license: BSD-style license found in the LICENSE file

package rand

import (
	"strconv"
	"testing"
	"unicode/utf8"
)

func TestStringCorrectLength(t *testing.T) {
	length := 10
	result := String(length)
	if len(result) != length {
		t.Errorf("Expected string of length %d, got %d", length, len(result))
	}
}

func TestStringWithNegativeOrZeroLength(t *testing.T) {
	testCases := []int{-1, 0} // Test cases with negative and zero length

	for _, length := range testCases {
		t.Run("Length="+strconv.Itoa(length), func(t *testing.T) {
			result := String(length)
			if result != "" {
				t.Errorf("String(%d) = %v, want empty string", length, result)
			}
		})
	}
}

func TestStringRandomness(t *testing.T) {
	length := 10
	result1 := String(length)
	result2 := String(length)
	if result1 == result2 {
		t.Error("Expected two different strings, got two identical ones")
	}
}

func TestStringEdgeCases(t *testing.T) {
	tests := []int{0, -1, 10000}
	for _, length := range tests {
		result := String(length)
		if length <= 0 && utf8.RuneCountInString(result) != 0 {
			t.Errorf("Expected empty string for length %d, got %s", length, result)
		}
		if length > 0 && utf8.RuneCountInString(result) != length {
			t.Errorf("Expected string of length %d, got %d", length, utf8.RuneCountInString(result))
		}
	}
}
