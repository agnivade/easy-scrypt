package scrypt

import (
	"bytes"
	"testing"
)

// TestSamePassphrase checks whether same passphrase returns different keys
// due to random salt everytime
func TestSamePassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"
	key1, err := EncryptPassphrase(passphrase, 34)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
	}
	t.Logf("Returned key is - %v", key1)

	var key2 []byte
	key2, err = EncryptPassphrase(passphrase, 34)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
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
	passphrase_list := []string{
		"Hello there how are you doing",
		"this is bad",
		"oug84-3T[wZHcx*';k;=m",
	}

	for _, item := range passphrase_list {
		key, err := EncryptPassphrase(item, 32)
		if err != nil {
			t.Errorf("Error returned: %s\n", err)
		}

		var result bool
		result, err = VerifyPassphrase(item, 32, key)
		if err != nil {
			t.Errorf("Error returned: %s\n", err)
		}
		if !result {
			t.Errorf("Passphrase did not match\n")
		}
	}
}

// TestFailVerifyPassphrase encrypts one passphrase and tests with another
// passphrase to verify whether it fails or not
func TestFailVerifyPassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"

	key, err := EncryptPassphrase(passphrase, 32)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
	}

	var result bool
	result, err = VerifyPassphrase("This should fail", 32, key)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
	}
	if result {
		t.Errorf("The outputs matched whereas it shouldn't have\n")
	}
}
