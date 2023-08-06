package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"

	"github.com/samar2170/cognitio/api/cognitio/api"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

func init() {
	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("Error reading config file: " + err.Error())
	}
	passwordDecryptionKey = []byte(viper.GetString("PASSWORD_DECRYPTION_KEY"))
}

var passwordDecryptionKey []byte

func encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(passwordDecryptionKey)
	if err != nil {
		return "", errors.New("Error during creation of cipher block:  " + err.Error())
	}
	cipherText := make([]byte, aes.BlockSize+len(password))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", errors.New("Error during reading of random bytes:  " + err.Error())
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(password))

	return hex.EncodeToString(cipherText), nil
}

func main() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	client := api.NewAuthServiceClient(conn)
	password, err := encryptPassword("test")
	if err != nil {
		log.Fatalf("could not encrypt password: %v", err)
	}
	log.Println("password: ", password)
	// response, err := client.Signup(context.Background(), &api.SignupRequest{
	// 	Email:    "test@test.co.in",
	// 	Username: "test",
	// 	Password: password,
	// })
	response, err := client.Login(context.Background(), &api.LoginRequest{
		Username: "test",
		Password: password,
	})
	if err != nil {
		log.Fatalf("could not signup: %v", err)
	}
	log.Printf("Response from server: %s", response.Token)
}
