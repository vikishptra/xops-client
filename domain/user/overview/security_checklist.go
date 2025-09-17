package domain_overview

import (
	"context"

	"xops-admin/model"
)

type SeverityCountTotalFindings struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Total    int64  `json:"total"`
}

type ResponseTotalBugStatusItem struct {
	TotalData int64                `json:"all_total_findings"`
	ListData  []TotalBugStatusItem `json:"list_data"`
}

// New types for paginated responses
type TotalBugStatusItem struct {
	ID            string `json:"id"`
	FindingsName  string `json:"findings_name"`
	FindingsTotal int64  `json:"findings_total"`
}

type SecurityChecklistItem struct {
	Key           string `json:"key"`
	ID            string `json:"id"`
	DateTime      string `json:"datetime"`
	HashID        string `json:"hashId"`
	Host          string `json:"host"`
	Method        string `json:"method"`
	StatusCode    int    `json:"status_code"`
	Tools         string `json:"tools"`
	URL           string `json:"url"`
	PentesterIP   string `json:"pentester_ip"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Validation    string `json:"validation"`
	Vulnerability string `json:"vulnerability"`
}

type DetailIdSecurityChecklistItem struct {
	Key           string `json:"key"`
	ID            string `json:"id"`
	DateTime      string `json:"datetime"`
	HashID        string `json:"hashId"`
	Host          string `json:"host"`
	Method        string `json:"method"`
	StatusCode    int    `json:"status_code"`
	Tools         string `json:"tools"`
	URL           string `json:"url"`
	PentesterIP   string `json:"pentester_ip"`
	Severity      string `json:"severity"`
	Status        string `json:"status"`
	Validation    string `json:"validation"`
	Vulnerability string `json:"vulnerability"`
	Request       string `json:"request"`
	Response      string `json:"response"`
}

// Pagination parameters
type PaginationParams struct {
	Size         int      `json:"size"`
	Status       string   `json:"status"`
	Urls         []string `json:"urls"` // Changed from Url string to Urls []string
	Validation   string   `json:"validation"`
	Period       int      `json:"period"`
	SortOrder    string   `json:"sort_order"` // "oldest_newest" atau "newest_oldest"
	LastPageTime string   `json:"last_page_time"`
	LastPageID   string   `json:"first_page_id"`
	Direction    string   `json:"direction"` // "next" atau "previous"
	Severity     string   `json:"severity"`
	Search       string   `json:"search"`
}

type SecurityChecklistTableResponse struct {
	Success    bool                    `json:"success"`
	Message    any                     `json:"message"`
	Data       []SecurityChecklistItem `json:"data"`
	Pagination PaginationInfo          `json:"pagination"`
}

type PaginationInfo struct {
	Size        int  `json:"size"`
	HasNext     bool `json:"has_next"`
	HasPrevious bool `json:"has_previous"`
}

type URLListParams struct {
	Search string `json:"search" form:"search"`
	Page   int    `json:"page" form:"page"`
	Limit  int    `json:"limit" form:"limit"`
}

// URLListResponse represents the response for URL list API
type URLListResponse struct {
	Success    bool           `json:"success"`
	Message    any            `json:"message"`
	Data       []URLItem      `json:"data"`
	Pagination PaginationInfo `json:"pagination"`
}

// URLItem represents a single URL item in the list
type URLItem struct {
	URL   string `json:"url"`
	Count int64  `json:"count"` // Number of records for this URL
}

type VulnerabilityItemResponse struct {
	Success    bool                `json:"success"`
	Message    any                 `json:"message"`
	Data       []VulnerabilityItem `json:"data"`
	Pagination PaginationInfo      `json:"pagination"`
}

type VulnerabilityItem struct {
	No            int    `json:"no"`
	Vulnerability string `json:"vulnerability"`
}

// Request/Response types
type BulkUpdateSecurityChecklistRequest struct {
	Updates []SecurityChecklistBulkUpdate `json:"updates"`
}

type SecurityChecklistBulkUpdate struct {
	// Required
	ID string `json:"id"`

	// Optional fields for update
	Severity      string `json:"severity,omitempty"`
	Status        string `json:"status,omitempty"`
	Validation    string `json:"validation,omitempty"`
	Vulnerability string `json:"vulnerability,omitempty"`
	// Additional fields needed for PostgreSQL insertion (from Elasticsearch document)
	Host        string `json:"host"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	Tool        string `json:"tools"`
	URL         string `json:"url"`
	PentesterIP string `json:"pentester_ip"`
	FlagDomain  string `json:"flag_domain,omitempty"`
	Request     string `json:"request,omitempty"`
	Response    string `json:"response,omitempty"`
}

type BulkUpdateSecurityChecklistResponse struct {
	Message       string `json:"message"`
	UpdatedCount  int    `json:"updated_count"`
	InsertedCount int    `json:"inserted_count"`
}

type SecurityCheklistUseCase interface {
	GetTotalFindings(ctx context.Context, domainName string) (*[]SeverityCountTotalFindings, error)
	GetDomainByClientID(id string) (*model.DomainClient, error)
	GetTotalBugStatusList(ctx context.Context, domain_overviewName string) (*ResponseTotalBugStatusItem, error)
	GetSecurityChecklistTable(ctx context.Context, domainName string, params PaginationParams) (*SecurityChecklistTableResponse, error)
	GetSecurityChecklistDetailByESID(ctx context.Context, esID string) (*DetailIdSecurityChecklistItem, error)
	GetURLList(ctx context.Context, flagDomain string, params URLListParams) (*URLListResponse, error)
	ListVulnerabilityNames(ctx context.Context, search string, page, limit int) ([]VulnerabilityItem, int64, error)
	BulkUpdateSecurityChecklist(ctx context.Context, req BulkUpdateSecurityChecklistRequest) (*BulkUpdateSecurityChecklistResponse, error)
}
