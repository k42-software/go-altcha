// @author: Brian Wojtczak
// @copyright: 2024 by Brian Wojtczak
// @license: BSD-style license found in the LICENSE file

package altcha

import (
	"log"
	"sync"
	"testing"
)

func TestBanSignature(t *testing.T) {
	// Reset bannedSignatures for testing
	bannedSignatures = [][]string{}

	signature := "testSignature"
	BanSignature(signature)

	if len(bannedSignatures) == 0 || len(bannedSignatures[0]) == 0 || bannedSignatures[0][0] != signature {
		t.Errorf("BanSignature failed to add signature")
	}

	log.Printf("bannedSignatures: %v", bannedSignatures)
}

func TestBanSignatureEmpty(t *testing.T) {
	// Reset bannedSignatures for testing
	bannedSignatures = [][]string{}

	BanSignature("")

	if len(bannedSignatures) != 0 {
		t.Errorf("BanSignature should not add empty signature")
	}
}

func TestIsSignatureBanned(t *testing.T) {
	// Reset bannedSignatures for testing
	bannedSignatures = [][]string{{"bannedSignature"}}

	if !IsSignatureBanned("bannedSignature") {
		t.Errorf("IsSignatureBanned failed to recognize a banned signature")
	}

	if !IsSignatureBanned("") {
		t.Errorf("IsSignatureBanned failed to recognize an empty signature")
	}

	if IsSignatureBanned("unbannedSignature") {
		t.Errorf("IsSignatureBanned incorrectly identified an unbanned signature")
	}
}

func TestConcurrency(t *testing.T) {
	// Reset bannedSignatures for testing
	bannedSignatures = [][]string{}

	var wg sync.WaitGroup
	signatures := []string{"sig1", "sig2", "sig3"}

	for _, sig := range signatures {
		wg.Add(1)
		go func(signature string) {
			defer wg.Done()
			BanSignature(signature)
		}(sig)
	}

	wg.Wait()

	if len(bannedSignatures) == 0 || len(bannedSignatures[0]) != len(signatures) {
		t.Errorf("BanSignature failed to handle concurrent access")
	}
}
