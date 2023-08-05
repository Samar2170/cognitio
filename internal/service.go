package internal

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaim struct {
	Username string `json:"username"`
	UserId   string `json:"user_cid"`
	jwt.RegisteredClaims
}

func getCIDForUser() string {
	return uuid.New().String()
}

func createToken(username string, userCID string) (string, error) {
	claims := UserClaim{
		username,
		userCID,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "cognitio",
			Subject:   "user token",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
func LoginUser(username string, encryptedPassword string) (string, error) {
	user, err := getUserByUsername(username)
	if err != nil {
		return "", err
	}
	password, err := decryptPassword(encryptedPassword)
	if err != nil {
		return "", err
	}
	if password != user.Password {
		return "", errors.New("invalid password")
	}
	return createToken(username, user.CID)
}

func SignupUser(email, username, encryptedPassword string) error {
	password, err := decryptPassword(encryptedPassword)
	if err != nil {
		return err
	}
	user := User{
		Email:    email,
		Username: username,
		Password: password,
		CID:      getCIDForUser(),
	}
	return user.create()
}
