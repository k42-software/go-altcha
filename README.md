# go-altcha

[ALTCHA](https://altcha.org/) is a simple self-hosted alternative to CAPTCHA.

This is an implementation of the server side in Go.

## Usage

The simplest way to use this code is as a HTTP handler middleware.

```go
package main

import (
	"github.com/k42-software/go-altcha/http" // altcha
	"net/http"
)

func main() {
	fileServer := http.FileServer(http.Dir("."))
	http.HandleFunc("/altcha.min.js", altcha.ServeJavascript)
	http.Handle("/protected.html", altcha.ProtectForm(fileServer))
	http.Handle("/", fileServer)
	_ = http.ListenAndServe(":3003", http.DefaultServeMux)
}
```

See the example directory for a more detailed working example.

Alternatively, you can call the ALTCHA library functions directly.

```go
package main

import "github.com/k42-software/go-altcha"

// Generate a challenge
challenge := altcha.NewChallenge()

// Generate a response
response, ok := altcha.SolveChallenge(challenge, altcha.DefaultComplexity)
if !ok {
    panic("failed to solve challenge")
}

// Validate the response
valid := altcha.ValidateResponse(response)

if valid {
    // Success
} else {
    // Failure
}
```

## License

This project is covered by a BSD-style license that can be found in the LICENSE file.

