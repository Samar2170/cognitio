package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func EncryptPassword(password string) string {
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

func DecryptPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	cipherTextBytes, err := hex.DecodeString(password)
	if err != nil {
		return "", errors.New("Error during hex decoding of password:  " + err.Error())
	}
	block, err := aes.NewCipher(passwordDecryptionKey)
	if err != nil {
		return "", errors.New("Error during creation of cipher block:  " + err.Error())
	}
	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherTextBytes, cipherTextBytes)
	return string(cipherTextBytes), nil
}

// func decryptPassword(password string) (string, error) {
// 	return password, nil
// }
