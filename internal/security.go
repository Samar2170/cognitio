package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func encryptPassword(password string) string {
	block, err := aes.NewCipher(passwordDecryptionKey)
	if err != nil {
		return ""
	}
	cipherText := make([]byte, aes.BlockSize+len(password))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return ""
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(password))

	return hex.EncodeToString(cipherText)
}

func decryptPassword(password string) (string, error) {
	cipherTextBytes, err := hex.DecodeString(password)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(passwordDecryptionKey)
	if err != nil {
		return "", err
	}
	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherTextBytes, cipherTextBytes)
	return string(cipherTextBytes), nil
}
