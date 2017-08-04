package scrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"golang.org/x/crypto/scrypt"
)

// DerivePassphrase returns a keylen_bytes+60 bytes of derived text
// from the input passphrase.
// It runs the scrypt function for this.
func DerivePassphrase(passphrase string, keylen_bytes int) ([]byte, error) {
	// Generate salt
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	// Set params
	var N int32 = 16384
	var r int32 = 8
	var p int32 = 1

	// Generate key
	key, err := scrypt.Key([]byte(passphrase),
		salt,
		int(N), // Must be a power of 2 greater than 1
		int(r),
		int(p), // r*p must be < 2^30
		keylen_bytes)
	if err != nil {
		return nil, err
	}

	// Appending the salt
	key = append(key, salt...)

	// Encoding the params to be stored
	buf := new(bytes.Buffer)
	for _, elem := range [3]int32{N, r, p} {
		err = binary.Write(buf, binary.LittleEndian, elem)
		if err != nil {
			return nil, err
		}
		key = append(key, buf.Bytes()...)
		buf.Reset()
	}

	// appending the sha-256 of the entire header at the end
	hash_digest := sha256.New()
	hash_digest.Write(key)
	if err != nil {
		return nil, err
	}
	hash := hash_digest.Sum(nil)
	key = append(key, hash...)

	return key, nil
}

// VerifyPassphrase takes the passphrase and the target_key to match against.
// And returns a boolean result whether it matched or not
func VerifyPassphrase(passphrase string, target_key []byte) (bool, error) {
	keylen_bytes := len(target_key) - 60
	// Get the master_key
	target_master_key := target_key[:keylen_bytes]
	// Get the salt
	salt := target_key[keylen_bytes:48]
	// Get the params
	var N, r, p int32

	err := binary.Read(bytes.NewReader(target_key[48:52]), // byte 48:52 for N
		binary.LittleEndian,
		&N)
	if err != nil {
		return false, err
	}

	err = binary.Read(bytes.NewReader(target_key[52:56]), // byte 52:56 for r
		binary.LittleEndian,
		&r)
	if err != nil {
		return false, err
	}

	err = binary.Read(bytes.NewReader(target_key[56:60]), // byte 56:60 for p
		binary.LittleEndian,
		&p)
	if err != nil {
		return false, err
	}
	source_master_key, err := scrypt.Key([]byte(passphrase),
		salt,
		int(N), // Must be a power of 2 greater than 1
		int(r),
		int(p), // r*p must be < 2^30
		keylen_bytes)
	if err != nil {
		return false, err
	}

	target_hash := target_key[60:]
	// Doing the sha-256 checksum at the last because we want the attacker
	// to spend as much time possible cracking
	hash_digest := sha256.New()
	_, err = hash_digest.Write(target_key[:60])
	if err != nil {
		return false, err
	}
	source_hash := hash_digest.Sum(nil)

	// ConstantTimeCompare returns ints. Converting it to bool
	key_comp := subtle.ConstantTimeCompare(source_master_key,
		target_master_key) != 0
	hash_comp := subtle.ConstantTimeCompare(target_hash,
		source_hash) != 0
	result := key_comp && hash_comp
	return result, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
