package internal

import (
	"errors"
	"fmt"
	"math/rand"
	"net/smtp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaim struct {
	Username string `json:"username"`
	UserCid  string `json:"user_cid"`
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
	password, err := DecryptPassword(encryptedPassword)
	if err != nil {
		return "", err
	}
	if password != user.Password {
		return "", errors.New("invalid password")
	}
	token, err := createToken(username, user.CID)
	if err != nil {
		return "", err
	}
	us := UserSession{
		User:      *user,
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	err = createModelInstance(&us)
	if err != nil {
		return "", err
	}
	return token, nil
}

func SignupUser(email, username, encryptedPassword string) (string, error) {
	password, err := DecryptPassword(encryptedPassword)
	if err != nil {
		return "", err
	}
	user := User{
		Email:    email,
		Username: username,
		Password: password,
		CID:      getCIDForUser(),
	}
	err = createModelInstance(&user)
	if err != nil {
		return "", err
	}
	// err = sendEmailVerification(&user)
	// if err != nil {
	// 	return "", err
	// }
	return user.CID, nil
}

func sendEmailVerification(user *User) error {
	otp := rand.Int()
	uv := UserSignupVerification{
		User:      *user,
		UserID:    user.ID,
		Email:     user.Email,
		OTP:       fmt.Sprintf("%d", otp),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Verified:  false,
	}
	err := createModelInstance(&uv)
	if err != nil {
		return err
	}
	template := fmt.Sprintf(`Hi`+user.Username+`,
	Welcome to Cognitio. Please verify your email by entering the following OTP:
	`+fmt.Sprintf("%d", otp)+`
	
	Thanks,
	`, user.Username, otp)
	message := []byte(template)
	auth := smtp.PlainAuth("", emailAccount, emailPassword, smtpHost)
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, emailAccount, []string{user.Email}, message)
	if err != nil {
		return err
	}
	return nil
}

func VerifyEmailOTP(userCID, otp string) error {
	user, err := getUserByCID(userCID)
	if err != nil {
		return err
	}
	uv, err := getUserVerificationByEmail(user.Email)
	if err != nil {
		return err
	}
	if uv.OTP != otp {
		return errors.New("invalid otp")
	}
	uv.Verified = true
	err = updateModelInstance(uv)
	if err != nil {
		return err
	}
	return nil
}

func VerifyToken(token string) (User, error) {
	empty := User{}
	claims := UserClaim{}
	tkn, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		return empty, err
	}
	if !tkn.Valid {
		return empty, errors.New("invalid token")
	}
	user, err := getUserByCID(claims.UserCid)
	if err != nil {
		return empty, err
	}
	return *user, nil
}
