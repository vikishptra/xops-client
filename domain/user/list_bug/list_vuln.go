package domain_listbug

import (
	"context"

	"xops-admin/model"
)

type ListVulnerabilityUseCase interface {
	Create(ctx context.Context, vuln *model.ListVulnerability) error
	GetByID(ctx context.Context, id int64) (*model.ListVulnerability, error)
	Update(ctx context.Context, vuln *model.ListVulnerability) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, cursorID, limit int, direction string) ([]model.ListVulnerability, bool, interface{}, interface{}, error)
}
