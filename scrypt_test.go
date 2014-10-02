package scrypt

import (
	"bytes"
	"testing"
)

// TestSamePassphrase checks whether same passphrase returns different keys
// due to random salt everytime
func TestSamePassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"
	key1, err := EncryptPassphrase(passphrase)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}
	t.Logf("Returned key is - %v", key1)

	var key2 []byte
	key2, err = EncryptPassphrase(passphrase)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}
	t.Logf("Returned key is - %v", key2)

	if bytes.Equal(key1, key2) {
		t.Errorf("The 2 keys are the same for the same passphrase. Key1- %b, Key2- %b",
			key1, key2)
	}

}

// TestVerifyPassphrase checks whether the same passphrase passes the verify
// function or not
func TestVerifyPassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"

	key, err := EncryptPassphrase(passphrase)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}

	var result bool
	result, err = VerifyPassphrase(passphrase, key)
	if err != nil {
		t.Errorf("Error returned: %s", err)
	}
	if !result {
		t.Errorf("Passphrase did not match")
	}
}
