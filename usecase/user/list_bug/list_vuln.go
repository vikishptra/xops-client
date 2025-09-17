package list_bug

import (
	"context"
	"errors"

	"xops-admin/domain"
	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/model"
)

type listVulnerabilityUseCase struct {
	repo domain.ListVulnerabilityRepository
}

func NewListVulnerabilityUseCase(repo domain.ListVulnerabilityRepository) domain_listbug.ListVulnerabilityUseCase {
	return &listVulnerabilityUseCase{repo: repo}
}

func (u *listVulnerabilityUseCase) Create(ctx context.Context, bug *model.ListVulnerability) error {
	exists, err := u.repo.IsTypeBugExists(ctx, bug.TypeBug)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("invalid type_bug: not found in type_bugs table")
	}
	return u.repo.Create(ctx, bug)
}

func (u *listVulnerabilityUseCase) GetByID(ctx context.Context, id int64) (*model.ListVulnerability, error) {
	return u.repo.GetByID(ctx, id)
}

func (u *listVulnerabilityUseCase) Update(ctx context.Context, vuln *model.ListVulnerability) error {
	return u.repo.Update(ctx, vuln)
}

func (u *listVulnerabilityUseCase) Delete(ctx context.Context, id int64) error {
	return u.repo.Delete(ctx, id)
}

func (u *listVulnerabilityUseCase) List(ctx context.Context, cursorID, limit int, direction string) ([]model.ListVulnerability, bool, interface{}, interface{}, error) {
	return u.repo.List(ctx, cursorID, limit, direction)
}
