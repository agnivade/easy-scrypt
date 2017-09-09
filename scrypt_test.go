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
		t.Errorf("DerivePassphrase failed with: %v\n", err)
		return
	}

	var key2 []byte
	key2, err = DerivePassphrase(passphrase, 34)
	if err != nil {
		t.Errorf("DerivePassphrase failed with: %v\n", err)
		return
	}

	if bytes.Equal(key1, key2) {
		t.Errorf("The 2 keys are the same for the same passphrase. Key1- %b, Key2- %b",
			key1, key2)
	}
}

// TestVerifyPassphrase checks whether the same passphrase passes the verify
// function or not
func TestVerifyPassphrase(t *testing.T) {
	passphrases := []struct {
		passphrase string
		length     int
	}{
		{"Hello there how are you doing", 32},
		{"this is bad", 34},
		{"oug84-3T[wZHcx*';k;=m", 20},
		{"指事字 zhǐshìzì", 1},
		{" الأَبْجَدِيَّة العَرَبِيَّة", 30},
	}

	for i, item := range passphrases {
		key, err := DerivePassphrase(item.passphrase, item.length)
		if err != nil {
			t.Errorf("[%d]: DerivePassphrase failed with: %v\n", i, err)
			return
		}

		var result bool
		result, err = VerifyPassphrase(item.passphrase, key)
		if err != nil {
			t.Errorf("[%d]: VerifyPassphrase failed with: %v\n", i, err)
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
		t.Errorf("DerivePassphrase failed with: %v\n", err)
		return
	}

	var result bool
	result, err = VerifyPassphrase("This should fail", key)
	if err != nil {
		t.Errorf("VerifyPassphrase failed with: %v\n", err)
		return
	}
	if result {
		t.Errorf("The outputs matched whereas it shouldn't have\n")
	}
}

// TestFailVerifyLenPassphrase derives one passphrase and tests with another
// passphrase of a smaller len to check that it does not panic
func TestFailVerifyLenPassphrase(t *testing.T) {
	_, err := VerifyPassphrase("This should not panic", []byte("s"))
	if err == nil {
		t.Errorf("Unexpected nil error. Expected error.")
		return
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
