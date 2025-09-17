package model

import "time"

type ListBug struct {
	Id                  int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	IdListVulnerability int64     `gorm:"type:bigint;not null" json:"id_vulnerability"`
	IdElastic           string    `gorm:"type:varchar(255)" json:"id_elastic"`
	Host                string    `gorm:"type:varchar(255);not null" json:"host"`
	Method              string    `gorm:"type:varchar(50);not null" json:"method"`
	StatusCode          int       `gorm:"type:bigint;not null" json:"status_code"`
	Tool                string    `gorm:"type:varchar(100);not null" json:"tools"`
	URL                 string    `gorm:"type:text;not null" json:"url"`
	PentesterIP         string    `gorm:"type:varchar(45);not null" json:"pentester_ip"`
	Severity            string    `gorm:"type:varchar(50);not null" json:"severity"`
	Status              string    `gorm:"type:varchar(50);not null" json:"status"`
	Validation          string    `gorm:"type:varchar(50);default:pending" json:"validation"`
	Vulnerability       string    `gorm:"type:varchar(255);not null" json:"vulnerability"`
	FlagDomain          string    `gorm:"type:varchar(255)" json:"flag_domain,omitempty"`
	Request             string    `gorm:"type:text" json:"request,omitempty"`
	Response            string    `gorm:"type:text" json:"response,omitempty"`
	CreatedAt           time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt           time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}
