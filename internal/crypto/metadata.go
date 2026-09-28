package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func EncryptFilenMetadata(plaintext, masterKey string) (string, error) {
	if masterKey == "" {
		return "", errors.New("master key is required")
	}
	key := pbkdf2.Key([]byte(masterKey), []byte(masterKey), 1, 32, sha512.New)
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create metadata cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create metadata GCM: %w", err)
	}
	randomBytes := make([]byte, 9)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate metadata nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(randomBytes)
	encrypted := gcm.Seal(nil, []byte(nonce), []byte(plaintext), nil)
	return "002" + string(nonce) + base64.StdEncoding.EncodeToString(encrypted), nil
}

func DecryptFilenMetadata(encrypted, masterKey string) (string, error) {
	if masterKey == "" {
		return "", errors.New("master key is required")
	}
	if len(encrypted) < 15 {
		return "", errors.New("filen metadata is too short")
	}
	if encrypted[:3] != "002" {
		return "", errors.New("unsupported filen metadata version")
	}
	nonce := []byte(encrypted[3:15])
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted[15:])
	if err != nil {
		return "", fmt.Errorf("decode filen metadata: %w", err)
	}
	key := pbkdf2.Key([]byte(masterKey), []byte(masterKey), 1, 32, sha512.New)
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create metadata cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create metadata GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt filen metadata: %w", err)
	}
	return string(plaintext), nil
}
