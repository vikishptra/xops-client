package security_checklist

import (
	"context"
	"fmt"

	"xops-admin/domain"
	domain_overview "xops-admin/domain/user/overview"
	"xops-admin/model"
)

type SecurityChecklistRepo struct {
	repo                  domain.SecurityChecklistRepository
	clientRepo            domain.ClientRepository
	listVuln              domain.ListVulnerabilityRepository
	bulkSecurityChecklist domain.BulkUpdateSecurityChecklistRepository
}

// BulkUpdateSecurityChecklist implements domain_overview.SecurityCheklistUseCase.
func (s *SecurityChecklistRepo) BulkUpdateSecurityChecklist(ctx context.Context, req domain_overview.BulkUpdateSecurityChecklistRequest) (*domain_overview.BulkUpdateSecurityChecklistResponse, error) {
	if len(req.Updates) == 0 {
		return nil, fmt.Errorf("no updates provided")
	}

	// Call repository
	err := s.bulkSecurityChecklist.UpdateSecurityChecklistItems(ctx, req.Updates)
	if err != nil {
		return nil, fmt.Errorf("failed to update checklist items: %w", err)
	}

	// Hitung berapa yang update vs insert (misalnya repo bisa return detail)
	// Untuk sekarang kita asumsi semua dianggap update
	resp := &domain_overview.BulkUpdateSecurityChecklistResponse{
		Message:       "Bulk update success",
		UpdatedCount:  len(req.Updates), // nanti bisa diubah sesuai hasil repo
		InsertedCount: 0,
	}

	return resp, nil
}

// ListVulnerabilityNames implements domain_overview.SecurityCheklistUseCase.
func (s *SecurityChecklistRepo) ListVulnerabilityNames(ctx context.Context, search string, page, limit int) ([]domain_overview.VulnerabilityItem, int64, error) {
	return s.listVuln.ListVulnerabilityNames(context.TODO(), search, page, limit)
}

// GetURLList implements domain_overview.SecurityCheklistUseCase.
func (s *SecurityChecklistRepo) GetURLList(ctx context.Context, flagDomain string, params domain_overview.URLListParams) (*domain_overview.URLListResponse, error) {
	return s.repo.GetURLList(context.TODO(), flagDomain, params)
}

// GetSecurityChecklistDetailByESID implements domain_overview.SecurityCheklistUseCase.
func (s *SecurityChecklistRepo) GetSecurityChecklistDetailByESID(ctx context.Context, esID string) (*domain_overview.DetailIdSecurityChecklistItem, error) {
	return s.repo.GetSecurityChecklistDetailByESID(context.TODO(), esID)
}

// GetTotalFindings - existing method (unchanged)
func (s *SecurityChecklistRepo) GetTotalFindings(ctx context.Context, domainName string) (*[]domain_overview.SeverityCountTotalFindings, error) {
	return s.repo.GetTotalFindings(ctx, domainName)
}

// GetTotalBugStatusList - new method with pagination and sorting
func (s *SecurityChecklistRepo) GetTotalBugStatusList(ctx context.Context, domainName string) (*domain_overview.ResponseTotalBugStatusItem, error) {
	return s.repo.GetTotalBugStatusList(ctx, domainName)
}

// GetSecurityChecklistTable - new method with pagination and sorting
func (s *SecurityChecklistRepo) GetSecurityChecklistTable(ctx context.Context, domainName string, params domain_overview.PaginationParams) (*domain_overview.SecurityChecklistTableResponse, error) {
	// Validate pagination parameters

	// Validate sort order
	if params.SortOrder == "" {
		params.SortOrder = "newest" // default sort
	}
	if params.SortOrder != "newest" && params.SortOrder != "oldest" {
		params.SortOrder = "newest" // fallback to default
	}

	return s.repo.GetSecurityChecklistTable(ctx, domainName, params)
}

// GetDomainByClientID - existing method (unchanged)
func (s *SecurityChecklistRepo) GetDomainByClientID(id string) (*model.DomainClient, error) {
	return s.clientRepo.GetDomainByClientID(id)
}

// Constructor - updated to implement the new interface
func NewSecurityChecklist(repo domain.SecurityChecklistRepository, clientRepo domain.ClientRepository, listVuln domain.ListVulnerabilityRepository, bulkSecurityChecklist domain.BulkUpdateSecurityChecklistRepository) domain_overview.SecurityCheklistUseCase {
	return &SecurityChecklistRepo{
		repo:                  repo,
		clientRepo:            clientRepo,
		listVuln:              listVuln,
		bulkSecurityChecklist: bulkSecurityChecklist,
	}
}
