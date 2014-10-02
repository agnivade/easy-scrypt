easy-scrypt
===========

This is a nice and simple wrapper in Go over the raw scrypt libraries available. There are just 2 calls exposed by the library(and should be!) which makes it super easy to embed in any of your projects.

You can use it to -

1. Safely encrypt and store passwords.
2. Encrypt a passphrase to get a derived key.
3. Let me know if you find other uses .. :)

The code is go fmt'd.

Implementation Details
----------------------

Usage
-----

```go
package main

import (
	"fmt"
	"github.com/agnivade/easy-scrypt"
)

func main() {
	passphrase := "Hello there this is a sample passphrase"

	key, err := scrypt.EncryptPassphrase(passphrase)
	if err != nil {
		fmt.Errorf("Error returned: %s\n", err)
	}

	fmt.Printf("Key returned - %v\n", key)
	var result bool

	result, err = scrypt.VerifyPassphrase(passphrase, key)
	if err != nil {
		fmt.Errorf("Error returned: %s\n", err)
	}
	if !result {
		fmt.Errorf("Passphrase did not match\n")
	} else {
		fmt.Printf("Passphrase matched successfully\n")
	}
}
```
