package internal

// accept login requests and provide token,
// accept token and provide user info

import (
	"github.com/samar2170/cognitio/pkg/db"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

var passwordDecryptionKey = []byte(viper.GetString("PASSWORD_DECRYPTION_KEY"))
var signingKey = []byte(viper.GetString("SIGNING_KEY"))

type User struct {
	*gorm.Model
	ID       uint   `gorm:"PrimaryIndex"`
	CID      string `gorm:"index,unique"`
	Email    string `gorm:"Unique"`
	Username string `gorm:"index,unique"`
	Password string
}

func (u *User) create() error {
	err := db.DB.Create(u).Error
	return err
}

func (u *User) update() error {
	err := db.DB.Save(u).Error
	return err
}
func (u *User) toJson() map[string]interface{} {
	return map[string]interface{}{
		"email":    u.Email,
		"username": u.Username,
		"user_id":  u.ID,
	}
}

func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.DB.Where("username = ?", username).First(&user).Error
	return &user, err
}
