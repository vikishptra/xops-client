// usecase/list_bug/list_bug.go
package list_bug

import (
	"context"

	"xops-admin/domain"
	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/model"
)

type ListBugTableUseCase struct {
	repo       domain.ListBugRepository // Perbaikan: menggunakan ListBugRepository bukan ListVulnerabilityRepository
	clientRepo domain.ClientRepository
}

func NewListBugTableUseCase(repo domain.ListBugRepository, clientRepo domain.ClientRepository) domain_listbug.ListBugUseCase {
	return &ListBugTableUseCase{repo: repo, clientRepo: clientRepo}
}

func (u *ListBugTableUseCase) GetBugs(ctx context.Context, filter domain.ListBugFilter) (*domain.ListBugResponse, error) {
	return u.repo.GetBugs(ctx, filter)
}
func (u *ListBugTableUseCase) GetDomainByClientID(id string) (*model.DomainClient, error) {
	return u.clientRepo.GetDomainByClientID(id)
}
