package db

import (
	"fmt"

	"github.com/spf13/viper"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DBURI string
var environment string
var DB *gorm.DB

func connect() {
	var err error
	if environment == "prod" {
		DB, err = gorm.Open(postgres.Open(DBURI), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
	} else {
		DB, err = gorm.Open(sqlite.Open("gorm.db"), &gorm.Config{})
	}
	if err != nil {
		panic(err)
	}
}
func loadEnvVars() {
	viper.SetConfigFile(".env")
	viper.ReadInConfig()

	DBURI = fmt.Sprintf("host=%s user=%s dbname=%s password=%s port=%s sslmode=disable",
		viper.Get("DBHOST"),
		viper.Get("DBUSER"),
		viper.Get("DBNAME"),
		viper.Get("DBPASSWORD"),
		viper.Get("DBPORT"),
	)
	environment = viper.GetString("ENVIRONMENT")
}
func init() {
	loadEnvVars()
	connect()
}
