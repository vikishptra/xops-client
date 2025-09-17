package model

import "time"

type DomainClient struct {
	Id        string    `gorm:"type:varchar(100);primary_key;not null" json:"id"`
	IdClient  string    `gorm:"type:varchar(100);primary_key;not null" json:"id_client"`
	Domain    string    `gorm:"type:text;not null" json:"domain" `
	Active    bool      `gorm:"type:bool;"`
	CreatedAt time.Time `gorm:"not null;default:now()"`
	UpdatedAt time.Time `gorm:"not null;default:now()"`
}
