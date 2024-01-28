# go-altcha

[ALTCHA](https://altcha.org/) is a simple self-hosted alternative to CAPTCHA.

This is an implementation of the server side in Go.

## Usage

```go
package main

import "github.com/k42-software/go-altcha"

// Step 1: Generate a challenge
challenge := altcha.NewChallenge()

// Step 2: Send the challenge to the client

// Step 3: Receive the response from the client

// Step 4: Validate the response
valid := altcha.ValidateResponse(response)

if valid {
    // Success
} else {
    // Failure
}
```

See the example directory for a working basic example.

## License

This project is covered by a BSD-style license that can be found in the LICENSE file.

