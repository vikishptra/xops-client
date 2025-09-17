// File: domain/repository.go
package domain

import (
	"context"

	domain_overview "xops-admin/domain/user/overview"
)

type ProxyTrafficDocument struct {
	ID            string `json:"id"`
	Time          string `json:"time"`
	Host          string `json:"host"`
	Method        string `json:"method"`
	StatusCode    int    `json:"status_code"`
	Tools         string `json:"tools"`
	URL           string `json:"url"`
	IP            string `json:"ip"`
	PentesterName string `json:"pentester_name"`
	Severity      string `json:"severity"`
	Validation    string `json:"validation"`
	Status        string `json:"status"`
	Vulnerability string `json:"vulnerability"`
	Request       string `json:"request"`
	Response      string `json:"response"`
}

type SearchResponse struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source ProxyTrafficDocument `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations map[string]interface{} `json:"aggregations,omitempty"`
}

type OverviewRepository interface {
	// Chart 1: Vulnerability Timeline
	GetVulnerabilityStats(ctx context.Context, days int, domainName, filter string) ([]domain_overview.VulnStat, error)

	// Chart 2: Bug Distributions
	GetBugSeverityDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.SeverityDistribution, error)
	GetBugStatusDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.StatusDistribution, error)
	GetBugValidationDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.ValidationDistribution, error)

	// Chart 3: Host Exposure and Pentester Activity
	GetHostBugsExposure(ctx context.Context, domainName string, period int) ([]domain_overview.HostExposure, error)
	GetPentestersActivity(ctx context.Context, domainName string, period int) ([]domain_overview.PentesterActivity, error)

	// Chart 4: Bug Type Frequency
	GetBugTypeFrequency(ctx context.Context, domainName string, period int) ([]domain_overview.BugTypeFrequency, error)

	//
	GetTotalFindingsWithTrend(
		ctx context.Context,
		domainName string,
	) (*domain_overview.ResponseTotalFindings, error)

	GetPentestersEffectiveness(ctx context.Context, domainName string, period int) ([]domain_overview.PentesterEffectiveness, error)

	GetLogActivity(ctx context.Context, params domain_overview.LogActivityPaginationParams) (*domain_overview.LogActivityResponse, error)
}
