// File: domain/repository.go
package domain

import (
	"context"

	domain_overview "xops-admin/domain/user/overview"
)

type SecurityChecklistRepository interface {
	GetTotalFindings(ctx context.Context, domainName string) (*[]domain_overview.SeverityCountTotalFindings, error)
	GetTotalBugStatusList(ctx context.Context, domain_overviewName string) (*domain_overview.ResponseTotalBugStatusItem, error)
	GetSecurityChecklistTable(ctx context.Context, domainName string, params domain_overview.PaginationParams) (*domain_overview.SecurityChecklistTableResponse, error)
	GetSecurityChecklistDetailByESID(ctx context.Context, esID string) (*domain_overview.DetailIdSecurityChecklistItem, error)
	GetURLList(ctx context.Context, flagDomain string, params domain_overview.URLListParams) (*domain_overview.URLListResponse, error)
}
