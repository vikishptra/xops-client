package domain_overview

import (
	"context"
	"time"

	"xops-admin/model"
)

type VulnStat struct {
	Name string  `json:"name" bson:"name"`
	Data []int64 `json:"data" bson:"data"`
}

type Label struct {
	Show     bool   `json:"show"`
	Position string `json:"position"`
}

type AreaStyle struct {
	Color string `json:"color"`
}

type LineStyle struct {
	Color string `json:"color"`
	Width int    `json:"width"`
}

type Emphasis struct {
	Focus string `json:"focus"`
}

type ChartData struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Stack     string    `json:"stack"`
	Label     Label     `json:"label"`
	AreaStyle AreaStyle `json:"areaStyle"`
	LineStyle LineStyle `json:"lineStyle"`
	Emphasis  Emphasis  `json:"emphasis"`
	Data      []int64   `json:"data"`
}

// Chart 2 structs - Bug Severity Distribution
type SeverityDistribution struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	StatusTotal int64      `json:"statusTotal"`
	Color       string     `json:"color"`
	ListsData   []HostData `json:"listsData"`
}

// Chart 2 structs - Bug Status Distribution
type StatusDistribution struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	StatusTotal int64      `json:"statusTotal"`
	Color       string     `json:"color"`
	ListsData   []HostData `json:"listsData"`
}

// Chart 2 structs - Bug Validation Distribution
type ValidationDistribution struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	StatusTotal int64      `json:"statusTotal"`
	Color       string     `json:"color"`
	ListsData   []HostData `json:"listsData"`
}

// Common struct for host data breakdown
type HostData struct {
	Description      string `json:"description"`
	DescriptionTotal int64  `json:"descriptionTotal"`
}

// Chart 3 structs - Host/Domain Bugs Exposure
type HostExposure struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
	Color string `json:"color"`
}
type SeverityCount struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Total    int64  `json:"total"`
}

// Chart 3 structs - Pentesters Activity (alternative to working hours)
type PentesterActivity struct {
	Name                string `json:"name"`
	Value               int64  `json:"value"`
	Color               string `json:"color"`
	PerDayWorkingHours  string `json:"perDayWorkingHours"`
	PerWeekWorkingHours string `json:"perWeekWorkingHours"`
	UniqueDays          int64  `json:"uniqueDays"` // Number of unique days worked
}

// Chart 4 structs - Bug Type Frequency
type BugTypeFrequency struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
	Color string `json:"color"`
}
type ResponseTotalFindings struct {
	TotalData int64                `json:"total_data"`
	ListData  []TotalFindingsCount `json:"list_data"`
}
type TotalFindingsCount struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Total       int    `json:"total"`
	TrendStatus string `json:"trend_status"` // "Up" atau "Down"
	TrendSum    string `json:"trend_sum"`    // persentase perubahan, contoh: "2%"

}
type PentesterEffectiveness struct {
	Key          string    `json:"key"`
	Name         string    `json:"name"`
	IP           string    `json:"ip"`
	TotalFinding int       `json:"totalFinding"`
	IsActive     bool      `json:"isActive"`
	LastActivity time.Time `json:"lastActivity"`
	Status       struct {
		IsActive    bool   `json:"isActive"`
		Description string `json:"description"`
	} `json:"status"`
}

type LogActivity struct {
	No        string `json:"no"`
	Id        string `json:"id"`
	Name      string `json:"name"`
	IPs       string `json:"ips"`
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
}
type LogActivityResponse struct {
	Data       []LogActivity  `json:"data"`
	Pagination PaginationInfo `json:"pagination"`
}
type LogActivityPaginationParams struct {
	Search    string `json:"search" query:"search"`         // Search untuk name dan IP
	StartDate string `json:"start_date" query:"start_date"` // Format: YYYY-MM-DD
	EndDate   string `json:"end_date" query:"end_date"`     // Format: YYYY-MM-DD
	Domain    string `json:"domain" query:"domain"`
}
type ResponseLogActivity struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Data       []LogActivity  `json:"data"`
		Pagination PaginationInfo `json:"pagination"`
	} `json:"data"`
}

type BugDiscoveryTimelineUseCase interface {
	//1
	GetVulnerabilityChart(ctx context.Context, period int, domainName, filter string) ([]ChartData, error)
	//2
	GetBugSeverityDistribution(ctx context.Context, domainName string, period int, status string) ([]SeverityDistribution, error)
	//
	GetBugStatusDistribution(ctx context.Context, domainName string, period int, status string) ([]StatusDistribution, error)
	//
	GetBugValidationDistribution(ctx context.Context, domainName string, period int, status string) ([]ValidationDistribution, error)

	GetHostBugsExposure(ctx context.Context, domainName string, period int) ([]HostExposure, error)

	GetPentestersActivityStats(ctx context.Context, domainName string, periode int) ([]PentesterActivity, error)

	GetBugTypeFrequency(ctx context.Context, domainName string, period int) ([]BugTypeFrequency, error)

	GetTotalFindingsWithTrend(
		ctx context.Context,
		domainName string,
	) (*ResponseTotalFindings, error)

	GetRealTimePentesterStatus(ctx context.Context, domainName string) ([]PentesterEffectiveness, error)

	GetLogActivity(ctx context.Context, params LogActivityPaginationParams) (*LogActivityResponse, error)
	GetDomainByClientID(id string) (*model.DomainClient, error)
}
