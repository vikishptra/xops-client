package domain

import (
	"context"
	"time"
)

type ListBugFilter struct {
	Search     string `json:"search" query:"search"`
	Severity   string `json:"severity" query:"severity"`
	Status     string `json:"status" query:"status"`
	FlagDomain string `json:"flag_domain" query:"flag_domain"`
	SortBy     string `json:"sort_by" query:"sort_by"`
	SortOrder  string `json:"sort_order" query:"sort_order"`
	Direction  string `json:"direction" query:"direction"`
	LastID     int    `json:"last_id" query:"last_id"`
	LastTime   string `json:"last_time" query:"last_time"` // TAMBAHKAN INI
	Convert    string `json:"convert" query:"convert"`     // NEW: For CSV export

	Limit int `json:"limit" query:"limit"`
}

// ListBugResponse represents paginated response
type ListBugResponse struct {
	Success    bool           `json:"success"`
	Message    any            `json:"message"`
	Data       []ListBug      `json:"data,omitempty"`     // Made optional for CSV
	CSVData    string         `json:"csv_data,omitempty"` // NEW: CSV data
	Pagination PaginationInfo `json:"pagination"`
}
type PaginationInfo struct {
	Size        int  `json:"size"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}
type ListBug struct {
	Id             int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	NameBug        string `gorm:"type:varchar(255);not null" json:"name_bug"`
	TypeBug        string `gorm:"type:varchar(255);not null" json:"type_bug"`
	DescriptionBug string `gorm:"type:varchar(255);not null" json:"description_bug"`
	Host           string `gorm:"type:varchar(255);not null" json:"host"`
	Method         string `gorm:"type:varchar(50);not null" json:"method"`
	StatusCode     int    `gorm:"not null" json:"status_code"`
	Tool           string `gorm:"type:varchar(100);not null" json:"tool"`
	URL            string `gorm:"type:text;not null" json:"url"`
	PentesterIP    string `gorm:"type:varchar(45);not null" json:"pentester_ip"`
	Severity       string `gorm:"type:varchar(50);not null" json:"severity"`
	Status         string `gorm:"type:varchar(50);not null" json:"status"`
	Validation     string `json:"validation"`
	Vulnerability  string `gorm:"type:varchar(255);not null" json:"vulnerability"`
	FlagDomain     string `gorm:"type:varchar(255)" json:"flag_domain,omitempty"`
	// Request       string    `gorm:"type:text" json:"request,omitempty"`
	// Response      string    `gorm:"type:text" json:"response,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// CursorInfo represents cursor information for pagination
type CursorInfo struct {
	LastID   string `json:"last_id"`
	LastTime string `json:"last_time"`
}
type ListBugRepository interface {
	GetBugs(ctx context.Context, filter ListBugFilter) (*ListBugResponse, error)
}
