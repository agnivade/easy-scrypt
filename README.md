easy-scrypt [![Build Status](https://travis-ci.org/agnivade/easy-scrypt.svg?branch=master)](https://travis-ci.org/agnivade/easy-scrypt) [![codecov](https://codecov.io/gh/agnivade/easy-scrypt/branch/master/graph/badge.svg)](https://codecov.io/gh/agnivade/easy-scrypt) [![GoDoc](https://godoc.org/github.com/agnivade/levenshtein?status.svg)](https://godoc.org/github.com/agnivade/levenshtein)
===========

This is a nice and simple wrapper in Go over the raw scrypt libraries available. There are just 2 calls exposed by the library(and should be!) which makes it super easy to embed in any of your projects.

You can use it to -

1. Safely hash passwords.
2. Hash a passphrase to get a derived key.
3. Let me know if you find other uses .. :)

Quick start
-----

```go
package main

import (
	"fmt"
	"github.com/agnivade/easy-scrypt"
)

func main() {
	passphrase := "Hello there this is a sample passphrase"

	key, err := scrypt.DerivePassphrase(passphrase, 32)
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

Implementation Details
----------------------

The scrypt call is invoked with these params -
N = 16384
r = 8
p = 1

The salt is randomly generated from the crypto/rand library which generates a cryptographically secure pseudorandom number.

The returned key will be of x+60 bytes in length where x is the key length passed to the call. The key returned is of this format -

```
array index starts from left.
<-----x-----><----16----><--4--><--4--><--4--><----32---->
    dKey          salt      N      r      p   sha-256 hash
```

A SHA-256 of the entire content(dKey+salt+n+r+p) is computed and stored at the end to just verify the integrity of the content.
