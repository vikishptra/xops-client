package config

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"xops-admin/model"
)

var DB *gorm.DB

func ConnectionToMPostGresDB(config *InitConfig) *gorm.DB {
	var err error
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai", config.DBHost, config.DBUserName, config.DBUserPassword, config.DBName, config.DBPort)
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the Database! \n", err.Error())
		os.Exit(1)
	}
	autoMigrate := DB.AutoMigrate(&model.Role{}, &model.User{}, &model.ListVulnerability{}, &model.ListBug{}, &model.ActivityLogPentester{}, &model.Client{}, &model.DomainClient{}, &model.TypeBug{})

	if autoMigrate != nil {
		log.Fatal("Migration Failed:  \n", err.Error())
		os.Exit(1)
	}

	log.Println("🚀 Connected Successfully to the Database")

	return DB
}
