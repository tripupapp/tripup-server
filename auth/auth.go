package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// AuthProviders contains the possible authorisation mechanisms
type AuthProviders struct {
	PhoneNumber	string
	Email		string
	AppleID 	string
}

func shasum256(value string) string {
	hasher := sha256.New()
	hasher.Write([]byte(value))
    return hex.EncodeToString(hasher.Sum(nil))
}
