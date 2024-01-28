//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import "github.com/k42-software/go-altcha/rand"

// Variables are used to allow for mocking in tests.
var (
	randomInt    = rand.Int    // func(minimum, maximum int) int
	randomString = rand.String // func(length int) string
)
