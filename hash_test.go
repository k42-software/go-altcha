//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"testing"
)

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		algorithm Algorithm
		want      string
	}{
		{SHA256, "SHA-256"},
		{SHA384, "SHA-384"},
		{SHA512, "SHA-512"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.algorithm.String(); got != tt.want {
				t.Errorf("Algorithm.String() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test for unknown algorithm (should panic)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for unknown algorithm, but did not panic")
		}
	}()
	_ = Algorithm(-1).String()
}

func TestAlgorithmFromString(t *testing.T) {
	tests := []struct {
		input string
		want  Algorithm
		valid bool
	}{
		{"SHA-256", SHA256, true},
		{"SHA-384", SHA384, true},
		{"SHA-512", SHA512, true},
		{"Invalid", UnknownAlgorithm, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, isValid := AlgorithmFromString(tt.input)
			if got != tt.want || isValid != tt.valid {
				t.Errorf("AlgorithmFromString(%v) = %v, %v, want %v, %v", tt.input, got, isValid, tt.want, tt.valid)
			}
		})
	}
}

func Test_generateHash(t *testing.T) {
	type args struct {
		algo   Algorithm
		salt   string
		number int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			SHA256.String(),
			args{
				SHA256,
				"test_salt",
				1234567890,
			},
			"07a8eb207f7a5c7ad9dd7b5f9e2d395cc3c68c0111635a2be0d97a8ee836f1ae",
		},
		{
			SHA384.String(),
			args{
				SHA384,
				"test_salt",
				1234567890,
			},
			"5042a3a44e29705b224bbfe07209b37f0c6eff38699c3716ffd50836dd821fece9b093bdb091336cb20fdfbca188d8ae",
		},
		{
			SHA512.String(),
			args{
				SHA512,
				"test_salt",
				1234567890,
			},
			"0a776fdbedc0ac558b8a7009a3eb409dbe536705e9b5823cacb6989f4918298d8f13337851ccd9d937ffcfb16f618ebb3fca38609baedb5274972a66b0808a96",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := generateHash(tt.args.algo, tt.args.salt, tt.args.number); got != tt.want {
				t.Errorf("generateHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHasherPanic(t *testing.T) {
	// Define a deferred function to recover from the panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for unknown hashing algorithm, but did not panic")
		}
	}()

	// Call getHasher with an invalid algorithm value to trigger panic
	_, _ = getHasher(UnknownAlgorithm)
}
