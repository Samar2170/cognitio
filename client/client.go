package main

import (
	"context"
	"log"

	"github.com/samar2170/cognitio/api/cognitio/api"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var passwordDecryptionKey = []byte(viper.GetString("PASSWORD_DECRYPTION_KEY"))

func encryptPassword(password string) string {
	return password
}

// func encryptPassword(password string) string {
// 	block, err := aes.NewCipher(passwordDecryptionKey)
// 	if err != nil {
// 		return ""
// 	}
// 	cipherText := make([]byte, aes.BlockSize+len(password))
// 	iv := cipherText[:aes.BlockSize]
// 	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
// 		return ""
// 	}
// 	stream := cipher.NewCFBEncrypter(block, iv)
// 	stream.XORKeyStream(cipherText[aes.BlockSize:], []byte(password))

// 	return hex.EncodeToString(cipherText)
// }

func main() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	client := api.NewAuthServiceClient(conn)
	password := encryptPassword("test")
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
