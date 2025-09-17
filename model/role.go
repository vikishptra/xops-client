package model

import "time"

type Role struct {
	Id        int       `gorm:"type:int;primary_key;not null" json:"id"`
	IdRole    []User    `gorm:"foreignKey:IdRole"`
	NameRole  string    `gorm:"type:varchar(100);not null" json:"name_role" `
	CreatedAt time.Time `gorm:"not null;default:now()"`
	UpdatedAt time.Time `gorm:"not null;default:now()"`
}
