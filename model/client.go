package model

import "time"

type Client struct {
	Id           string         `gorm:"type:varchar(100);primary_key;not null" json:"id"`
	IdUser       string         `gorm:"type:varchar(100);not null" json:"id_user"`
	LogoCompany  string         `gorm:"type:varchar(100);not null" json:"logo_company" `
	CompanyName  string         `gorm:"type:text;not null" json:"company_name" `
	DomainClient []DomainClient `gorm:"foreignKey:IdClient;constraint:OnDelete:CASCADE"`
	StartDate    time.Time      `gorm:"not null"`
	EndDate      time.Time      `gorm:"not null"`
}
