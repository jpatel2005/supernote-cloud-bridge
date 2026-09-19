package crypto

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

type DerivedKeys struct {
	MasterKeys      string
	DerivedPassword string
}

func DeriveFilenKeys(password []byte, salt []byte) (DerivedKeys, error) {
	if len(password) == 0 {
		return DerivedKeys{}, errors.New("password is required")
	}
	if len(salt) == 0 {
		return DerivedKeys{}, errors.New("salt is required")
	}
	derivedKey := pbkdf2.Key(password, salt, 200_000, 64, sha512.New)
	defer ZeroBytes(derivedKey)

	derivedKeyHex := hex.EncodeToString(derivedKey)

	derivedPassword := derivedKeyHex[len(derivedKeyHex)/2:]
	derivedMasterKeys := derivedKeyHex[:len(derivedKeyHex)/2]

	passwordHash := sha512.Sum512([]byte(derivedPassword))
	derivedPassword = hex.EncodeToString(passwordHash[:])

	return DerivedKeys{
		MasterKeys:      derivedMasterKeys,
		DerivedPassword: derivedPassword,
	}, nil
}

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
