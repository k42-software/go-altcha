//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package rand

import (
	"crypto/rand"
	"math/big"
)

func Int(minimum, maximum int) int {
	maxBigInt := big.NewInt(int64(maximum - minimum))
	number, err := rand.Int(rand.Reader, maxBigInt)
	if err != nil {
		panic(err) // this should never happen
	}
	return minimum + int(number.Int64())
}
