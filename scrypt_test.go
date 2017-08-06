package scrypt

import (
	"bytes"
	"testing"
)

// TestSamePassphrase checks whether same passphrase returns different keys
// due to random salt everytime
func TestSamePassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"
	key1, err := DerivePassphrase(passphrase, 34)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
		return
	}
	t.Logf("Returned key is - %v", key1)

	var key2 []byte
	key2, err = DerivePassphrase(passphrase, 34)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
		return
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
	passphrase_list := []struct {
		passphrase string
		length     int
	}{
		{"Hello there how are you doing", 32},
		{"this is bad", 34},
		{"oug84-3T[wZHcx*';k;=m", 20},
		{"指事字 zhǐshìzì", 1},
		{" الأَبْجَدِيَّة العَرَبِيَّة", 30},
	}

	for _, item := range passphrase_list {
		key, err := DerivePassphrase(item.passphrase, item.length)
		if err != nil {
			t.Errorf("Error returned: %s\n", err)
			return
		}

		var result bool
		result, err = VerifyPassphrase(item.passphrase, key)
		if err != nil {
			t.Errorf("Error returned: %s\n", err)
			return
		}
		if !result {
			t.Errorf("Passphrase did not match\n")
		}
	}
}

// TestFailVerifyPassphrase derives one passphrase and tests with another
// passphrase to verify whether it fails or not
func TestFailVerifyPassphrase(t *testing.T) {
	passphrase := "Hello there how are you doing"

	key, err := DerivePassphrase(passphrase, 32)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
		return
	}

	var result bool
	result, err = VerifyPassphrase("This should fail", key)
	if err != nil {
		t.Errorf("Error returned: %s\n", err)
		return
	}
	if result {
		t.Errorf("The outputs matched whereas it shouldn't have\n")
	}
}

func BenchmarkDerivePassphrase(b *testing.B) {
	passphrase := "Hello there how are you doing"
	for n := 0; n < b.N; n++ {
		DerivePassphrase(passphrase, 32)
	}
}

func BenchmarkVerifyPassphrase(b *testing.B) {
	passphrase := "Hello there how are you doing"
	key, _ := DerivePassphrase(passphrase, 32)

	for n := 0; n < b.N; n++ {
		VerifyPassphrase(passphrase, key)
	}
}
