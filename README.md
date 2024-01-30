# go-altcha

[ALTCHA](https://altcha.org/) is a simple self-hosted alternative to CAPTCHA.

This is an implementation of the server side in Go.

## Caveats

This implementation deviates from the [specification](https://altcha.org/docs/)
in two minor ways:

1. The signatures are encoded using base64 instead of hex. This provides a more
   compact representation, and is still compatible.

2. The HTTP handler middleware adds a `WWW-Authenticate` header when outputting
   the JSON formatted challenge, and returns a status code of 200. This is 
   unnecessary, and technically incorrect. However, it allows for using the
   widget and the M2M variant with the same endpoint.


This was written for testing and comparison with other alternatives for CAPTCHA.
The code is intended to be suitable for production use. However, I have not 
evaluated the effectiveness of this challenge/response algorithm against real
world adversaries. Similar proof-of-work challenges exist, such as
[Hashcash](https://en.wikipedia.org/wiki/Hashcash), which I have seen 
implemented in production systems with varying success.

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
valid := altcha.ValidateResponse(response, true)

if valid {
    // Success
} else {
    // Failure
}
```

## License

This project is covered by a BSD-style license that can be found in the LICENSE file.

