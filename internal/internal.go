package internal

import (
	"github.com/samar2170/cognitio/pkg/db"
	"github.com/spf13/viper"
)

const (
	smtpHost = "smtp.gmail.com"
	smtpPort = "587"
)

var passwordDecryptionKey []byte
var signingKey []byte
var emailAccount string
var emailPassword string

func loadEnvVariables() {
	viper.SetConfigFile(".env")
	viper.ReadInConfig()

	passwordDecryptionKey = []byte(viper.GetString("PASSWORD_DECRYPTION_KEY"))
	signingKey = []byte(viper.GetString("SIGNING_KEY"))
	emailAccount = viper.GetString("EMAIL_ACCOUNT")
	emailPassword = viper.GetString("EMAIL_PASSWORD")
}
func init() {
	loadEnvVariables()
	db.DB.AutoMigrate(User{})
	db.DB.AutoMigrate(UserSession{})
	db.DB.AutoMigrate(UserSignupVerification{})
}
