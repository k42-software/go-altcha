//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strconv"
	"sync"
)

type Algorithm int

const (
	UnknownAlgorithm Algorithm = iota
	SHA256
	SHA384
	SHA512
)

func (algorithm Algorithm) String() string {
	switch algorithm {
	case SHA256:
		return "SHA-256"
	case SHA384:
		return "SHA-384"
	case SHA512:
		return "SHA-512"
	default:
		panic("unknown hashing algorithm")
	}
}

func AlgorithmFromString(algo string) (Algorithm, bool) {
	switch algo {
	case "SHA-256":
		return SHA256, true
	case "SHA-384":
		return SHA384, true
	case "SHA-512":
		return SHA512, true
	default:
		return UnknownAlgorithm, false
	}
}

var hasherPoolSha256 = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

var hasherPoolSha384 = sync.Pool{
	New: func() interface{} {
		return sha512.New384()
	},
}

var hasherPoolSha512 = sync.Pool{
	New: func() interface{} {
		return sha512.New()
	},
}

func getHasher(algo Algorithm) (hasher hash.Hash, put func()) {
	switch algo {
	case SHA256:
		hasher = hasherPoolSha256.Get().(hash.Hash)
		put = func() {
			hasher.Reset()
			hasherPoolSha256.Put(hasher)
		}
	case SHA384:
		hasher = hasherPoolSha384.Get().(hash.Hash)
		put = func() {
			hasher.Reset()
			hasherPoolSha384.Put(hasher)
		}
	case SHA512:
		hasher = hasherPoolSha512.Get().(hash.Hash)
		put = func() {
			hasher.Reset()
			hasherPoolSha512.Put(hasher)
		}
	default:
		panic("unknown hashing algorithm")
	}
	return hasher, put
}

func generateHash(algo Algorithm, salt string, number int) string {
	hasher, put := getHasher(algo)
	defer put()
	hasher.Write([]byte(salt))
	hasher.Write([]byte(strconv.Itoa(number)))
	return hex.EncodeToString(hasher.Sum(nil))
}
