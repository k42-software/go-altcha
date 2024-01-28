//  @author: Brian Wojtczak
//  @copyright: 2024 by Brian Wojtczak
//  @license: BSD-style license found in the LICENSE file

package altcha

import (
	"sync"
	"time"
)

const defaultSecretsRotationInterval = 5 * time.Minute

var (
	currentSecret         string
	previousSecret        string
	secretsRotationTicker *time.Ticker
	secretsMutex          = &sync.RWMutex{}
)

// GetSecrets returns the current and previous secrets used for the hmac.
func GetSecrets() (current, previous string) {
	secretsMutex.RLock()
	if len(currentSecret) == 0 { // not initialised yet
		secretsMutex.RUnlock()
		SetSecretsRotationInterval(defaultSecretsRotationInterval)
		secretsMutex.RLock()
	}
	defer secretsMutex.RUnlock()
	return currentSecret, previousSecret
}

// RotateSecrets immediately generates a new secret and replaces the previous
// secret with the current secret. This is concurrency safe and will block
// until complete.
func RotateSecrets() {
	secretsMutex.Lock()
	defer secretsMutex.Unlock()
	rotateSecrets()
}

// WARNING: Ensure the mutex is locked before calling this function.
func rotateSecrets() {
	previousSecret = currentSecret
	currentSecret = randomString(32)
}

// SetSecretsRotationInterval sets the interval at which secrets are automatically
// rotated. Setting the interval to 0 will disable automatic rotation.
func SetSecretsRotationInterval(interval time.Duration) {
	secretsMutex.Lock()
	defer secretsMutex.Unlock()
	if secretsRotationTicker != nil {
		secretsRotationTicker.Stop()
	}
	if interval > 0 {
		if len(currentSecret) == 0 { // not initialised yet
			currentSecret = randomString(32)
		}
		rotateSecrets()
		secretsRotationTicker = time.NewTicker(interval)
		go func() {
			defer secretsRotationTicker.Stop()
			for range secretsRotationTicker.C {
				RotateSecrets()
			}
		}()
	}
}
