//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"sync/atomic"
	"testing"
)

func TestSign(t *testing.T) {

	// Override randomString for deterministic behavior
	randomString = func(length int) string {
		const fakeRandomString = "0V5xzYiSFmY1swbbkwIoAgbWaiw7yJvZ"
		return fakeRandomString
	}
	RotateSecrets() // Rotate secrets so that the fake random string is used

	const exampleText = "The quick brown fox jumps over the lazy dog"
	type args struct {
		algo Algorithm
		text string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			SHA256.String(),
			args{SHA256, exampleText},
			"687b7d0bf0b61d2534061f5b352427a6654a3d19997b9042f486fabed8a5e0b8",
		},
		{
			SHA384.String(),
			args{SHA384, exampleText},
			"122b2be34a47d9b485070964d2f3211e07995e546eb0c5bc4768c8f6a7c4746b42eb73dd84576f9871d49d8acd763348",
		},
		{
			SHA512.String(),
			args{SHA512, exampleText},
			"1ef9aadfcdbc66bdc02019d407a082e74c55074c8d537f2caeb400a0963484b5d8c10772eaae7a0616d3537e9676666efb13b67872a00b60dec7446cfa1421e5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sign(tt.args.algo, tt.args.text); got != tt.want {
				t.Errorf("Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {

	// Override randomString for deterministic behavior
	randomString = func(length int) string {
		const fakeRandomString = "0V5xzYiSFmY1swbbkwIoAgbWaiw7yJvZ"
		return fakeRandomString
	}
	RotateSecrets() // Rotate secrets so that the fake random string is used

	const exampleText = "The quick brown fox jumps over the lazy dog"
	type args struct {
		algo      Algorithm
		text      string
		signature string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"Valid Signature with SHA256",
			args{
				SHA256,
				exampleText,
				"687b7d0bf0b61d2534061f5b352427a6654a3d19997b9042f486fabed8a5e0b8",
			},
			true,
		},
		{
			"Invalid Signature with SHA256",
			args{
				SHA256,
				exampleText,
				"invalid_signature",
			},
			false,
		},
		{
			"Valid Signature with SHA384",
			args{
				SHA384,
				exampleText,
				"122b2be34a47d9b485070964d2f3211e07995e546eb0c5bc4768c8f6a7c4746b42eb73dd84576f9871d49d8acd763348",
			},
			true,
		},
		{
			"Invalid Signature with SHA384",
			args{
				SHA384,
				exampleText,
				"invalid_signature",
			},
			false,
		},
		{
			"Valid Signature with SHA512",
			args{
				SHA512,
				exampleText,
				"1ef9aadfcdbc66bdc02019d407a082e74c55074c8d537f2caeb400a0963484b5d8c10772eaae7a0616d3537e9676666efb13b67872a00b60dec7446cfa1421e5",
			},
			true,
		},
		{
			"Invalid Signature with SHA512",
			args{
				SHA512,
				exampleText,
				"invalid_signature",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifySignature(tt.args.algo, tt.args.text, tt.args.signature); got != tt.want {
				t.Errorf("VerifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureValidityAfterSecretRotations(t *testing.T) {
	// Setup: Override randomString and track calls to generate different secrets
	var rotationCount int32
	randomString = func(length int) string {
		currentRotation := atomic.LoadInt32(&rotationCount)
		switch currentRotation {
		case 0:
			return "0V5xzYiSFmY1swbbkwIoAgbWaiw7yJvZ" // First secret
		case 1:
			return "1K7xwZjTHfM2tRbbLwJnBgbXcw8zKwXW" // Second secret
		default:
			return "2L8ywAkUIgN3uSccMxKoCgdYdx9lLyXY" // Third secret and onwards
		}
	}

	// Function to simulate secret rotation
	rotateSecret := func() {
		atomic.AddInt32(&rotationCount, 1)
		RotateSecrets()
	}

	const exampleText = "The quick brown fox jumps over the lazy dog"
	algo := SHA256
	originalSignature := Sign(algo, exampleText)

	// No Rotation: Signature should be valid
	t.Run("No Rotation", func(t *testing.T) {
		if !VerifySignature(algo, exampleText, originalSignature) {
			t.Errorf("Signature should be valid with zero rotations")
		}
	})

	// First Rotation: Signature should still be valid
	t.Run("First Rotation", func(t *testing.T) {
		rotateSecret()
		if !VerifySignature(algo, exampleText, originalSignature) {
			t.Errorf("Signature should be valid after one rotation")
		}
	})

	// Second Rotation: Signature should now be invalid
	t.Run("Second Rotation", func(t *testing.T) {
		rotateSecret()
		if VerifySignature(algo, exampleText, originalSignature) {
			t.Errorf("Signature should be invalid after two rotations")
		}
	})
}

func TestSignPanicOnEmptySecret(t *testing.T) {

	// Override randomString to return an empty string
	originalRandomString := randomString
	randomString = func(length int) string {
		return ""
	}
	defer func() {
		// Restore the original randomString after the test
		randomString = originalRandomString

		// Check for panic
		if r := recover(); r == nil {
			t.Errorf("Expected panic for empty secret, but did not panic")
		}
	}()

	// Rotate secrets to set the current secret to an empty string
	RotateSecrets()

	// Call Sign with valid parameters, expecting a panic due to empty secret
	_ = Sign(SHA256, "test text")
}
