//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"sort"
	"sync"
)

const defaultBanSliceSize = 10

var (
	bannedSignatures [][]string
	bannedMutex      = &sync.RWMutex{}
)

// BanSignature adds the given signature to the list of banned signatures.
func BanSignature(signature string) {
	if len(signature) == 0 {
		return
	}

	bannedMutex.Lock()
	defer bannedMutex.Unlock()

	if len(bannedSignatures) == 0 {
		bannedSignatures = make([][]string, 1, 2)
		bannedSignatures[0] = []string{}
	}

	if len(bannedSignatures[0]) == 0 {
		bannedSignatures[0] = make([]string, 0, defaultBanSliceSize)
	}

	bannedSignatures[0] = append(bannedSignatures[0], signature)
	sort.Strings(bannedSignatures[0])

	return
}

// IsSignatureBanned checks if the given signature is banned.
func IsSignatureBanned(signature string) bool {
	if len(signature) == 0 {
		return true // empty signature is always banned
	}

	bannedMutex.RLock()
	defer bannedMutex.RUnlock()

	for _, list := range bannedSignatures {
		for _, entry := range list {
			if entry == signature {
				return true
			}
		}
	}

	return false
}

func rotateBannedSignatureLists() {
	bannedMutex.Lock()
	defer bannedMutex.Unlock()

	if len(bannedSignatures) == 0 {
		return
	}

	if len(bannedSignatures) == 2 && len(bannedSignatures[1]) == 0 && len(bannedSignatures[0]) == 0 {
		return
	}

	bannedSignatures = [][]string{
		make([]string, 0, defaultBanSliceSize),
		bannedSignatures[0],
	}
}

func init() {
	AddSecretsRotationCallback(rotateBannedSignatureLists)
}
