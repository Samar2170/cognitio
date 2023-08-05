package internal_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

var passwordDecryptionKey []byte

func encryptPasswordP(password string) string {
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

func decryptPasswordP(password string) (string, error) {
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

func TestSecurity(t *testing.T) {
	os.Setenv("PASSWORD_DECRYPTION_KEY", "12345678901234567890123456789012")
	defer os.Unsetenv("PASSWORD_DECRYPTION_KEY")
	passwordDecryptionKey = []byte(os.Getenv("PASSWORD_DECRYPTION_KEY"))
	password := "test"
	encryptedPassword := encryptPasswordP(password)
	t.Log("encryptedPassword: ", encryptedPassword)
	decryptedPassword, err := decryptPasswordP(encryptedPassword)
	t.Log("decryptedPassword: ", decryptedPassword)
	if err != nil {
		t.Error(err)
	}
	if decryptedPassword != password {
		t.Error("decrypted password is not equal to original password")
	}
	t.Log("TestSecurity passed")
}
