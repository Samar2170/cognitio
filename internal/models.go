package internal

// accept login requests and provide token,
// accept token and provide user info

import (
	"errors"
	"reflect"

	"github.com/samar2170/cognitio/pkg/db"
	"gorm.io/gorm"
)

type DBModel interface {
	create() error
	update() error
}

type User struct {
	*gorm.Model
	ID       uint   `gorm:"PrimaryIndex"`
	CID      string `gorm:"uniqueIndex"`
	Email    string `gorm:"unique"`
	Username string `gorm:"uniqueIndex"`
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

func getUserByCID(cid string) (*User, error) {
	var user User
	err := db.DB.Where("c_id = ?", cid).First(&user).Error
	return &user, err
}

type UserSession struct {
	*gorm.Model
	ID        uint   `gorm:"PrimaryIndex"`
	User      User   `gorm:"foreignKey:UserID"`
	SessionID string `gorm:"index"`
	UserID    uint   `gorm:"index"`
	Token     string `gorm:"index"`
	ExpiresAt int64  `gorm:"index"`
	LoggedOut bool   `gorm:"index"`
}

func (u *UserSession) create() error {
	err := db.DB.Create(u).Error
	return err
}

func (u *UserSession) update() error {
	err := db.DB.Save(u).Error
	return err
}

type UserSignupVerification struct {
	*gorm.Model
	ID        uint   `gorm:"PrimaryIndex"`
	User      User   `gorm:"foreignKey:UserID"`
	UserID    uint   `gorm:"index"`
	Email     string `gorm:"index"`
	OTP       string `gorm:"index"`
	ExpiresAt int64  `gorm:"index"`
	Verified  bool   `gorm:"index"`
}

func (u *UserSignupVerification) create() error {
	err := db.DB.Create(u).Error
	return err
}
func (u *UserSignupVerification) update() error {
	err := db.DB.Save(u).Error
	return err
}
func getUserVerificationByEmail(email string) (*UserSignupVerification, error) {
	var user UserSignupVerification
	err := db.DB.Where("email = ?", email).First(&user).Error
	return &user, err
}

func createModelInstance(instance DBModel) error {
	err := instance.create()
	modelName := reflect.TypeOf(instance).Name()
	switch err {
	case nil:
		return nil
	case gorm.ErrDuplicatedKey:
		return errors.New("[gorm]:ErrDuplicatedKey" + modelName + " already exists")
	case gorm.ErrForeignKeyViolated:
		return errors.New("[gorm]:ErrForeignKeyViolated" + modelName + " missing foreign key")
	default:
		return err
	}
}

func updateModelInstance(instance DBModel) error {
	err := instance.update()
	modelName := reflect.TypeOf(instance).Name()
	switch err {
	case nil:
		return nil
	case gorm.ErrRecordNotFound:
		return errors.New("[gorm]:ErrRecordNotFound" + modelName + " does not exist")
	case gorm.ErrInvalidTransaction:
		return errors.New("[gorm]:ErrInvalidTransaction" + modelName + " invalid transaction")
	default:
		return err
	}
}
