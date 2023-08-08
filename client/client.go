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
	"google.golang.org/grpc/credentials/insecure"
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

type User struct {
	Username string
	UserCid  string
}

func main() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	client := api.NewAuthServiceClient(conn)
	token, err := login(&client, "test", "test")
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}
	log.Printf("Token: %s", token)

	user, err := verifyToken(&client, token)
	if err != nil {
		log.Fatalf("could not verify token: %v", err)
	}
	log.Printf("User: %s, %s", user.Username, user.UserCid)

}

func verifyToken(c *api.AuthServiceClient, token string) (User, error) {
	response, err := (*c).Authenticate(context.Background(), &api.AuthRequest{
		Token: token,
	})
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}
	log.Printf("Response from server: %s, %s", response.Username, response.UserCid)
	return User{
		Username: response.Username,
		UserCid:  response.UserCid,
	}, nil
}

func login(c *api.AuthServiceClient, username, password string) (string, error) {
	password, err := encryptPassword(password)
	if err != nil {
		return "", err
	}
	response, err := (*c).Login(context.Background(), &api.LoginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		log.Fatalf("could not login: %v", err)
	}
	log.Printf("Response from server: %s", response.Token)

	return response.Token, nil
}
