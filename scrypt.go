package scrypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// Some constants used throughout the code
const (
	N                = 16384
	r                = 8
	p                = 1
	metadataLenBytes = 60
	saltLenBytes     = 16
)

// DerivePassphrase returns a keylenBytes+60 bytes of derived text
// from the input passphrase.
// It runs the scrypt function for this.
func DerivePassphrase(passphrase string, keylenBytes int) ([]byte, error) {
	// Generate salt
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}

	// Generate key
	key, err := scrypt.Key([]byte(passphrase),
		salt,
		N, // Must be a power of 2 greater than 1
		r,
		p, // r*p must be < 2^30
		keylenBytes)
	if err != nil {
		return nil, err
	}

	// Appending the salt
	key = append(key, salt...)

	// Encoding the params to be stored
	buf := &bytes.Buffer{}
	for _, elem := range [3]int{N, r, p} {
		err = binary.Write(buf, binary.LittleEndian, int32(elem))
		if err != nil {
			return nil, err
		}
	}
	key = append(key, buf.Bytes()...)

	// appending the sha-256 of the entire header at the end
	hashDigest := sha256.New()
	_, err = hashDigest.Write(key)
	if err != nil {
		return nil, err
	}
	hash := hashDigest.Sum(nil)
	key = append(key, hash...)

	return key, nil
}

// VerifyPassphrase takes the passphrase and the targetKey to match against.
// And returns a boolean result whether it matched or not
func VerifyPassphrase(passphrase string, targetKey []byte) (bool, error) {
	keylenBytes := len(targetKey) - metadataLenBytes
	if keylenBytes < 1 {
		return false, errors.New("Invalid targetKey length")
	}
	// Get the master_key
	targetMasterKey := targetKey[:keylenBytes]
	// Get the salt
	salt := targetKey[keylenBytes : keylenBytes+saltLenBytes]
	// Get the params
	var N, r, p int32
	paramsStartIndex := keylenBytes + saltLenBytes

	err := binary.Read(bytes.NewReader(targetKey[paramsStartIndex:paramsStartIndex+4]), // 4 bytes for N
		binary.LittleEndian,
		&N)
	if err != nil {
		return false, err
	}

	err = binary.Read(bytes.NewReader(targetKey[paramsStartIndex+4:paramsStartIndex+8]), // 4 bytes for r
		binary.LittleEndian,
		&r)
	if err != nil {
		return false, err
	}

	err = binary.Read(bytes.NewReader(targetKey[paramsStartIndex+8:paramsStartIndex+12]), // 4 bytes for p
		binary.LittleEndian,
		&p)
	if err != nil {
		return false, err
	}
	sourceMasterKey, err := scrypt.Key([]byte(passphrase),
		salt,
		int(N), // Must be a power of 2 greater than 1
		int(r),
		int(p), // r*p must be < 2^30
		keylenBytes)
	if err != nil {
		return false, err
	}

	targetHash := targetKey[paramsStartIndex+12:]
	// Doing the sha-256 checksum at the last because we want the attacker
	// to spend as much time possible cracking
	hashDigest := sha256.New()
	_, err = hashDigest.Write(targetKey[:paramsStartIndex+12])
	if err != nil {
		return false, err
	}
	sourceHash := hashDigest.Sum(nil)

	// ConstantTimeCompare returns ints. Converting it to bool
	keyComp := subtle.ConstantTimeCompare(sourceMasterKey, targetMasterKey) != 0
	hashComp := subtle.ConstantTimeCompare(targetHash, sourceHash) != 0
	result := keyComp && hashComp
	return result, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLenBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
