package domain_listbug

import (
	"context"

	"xops-admin/domain"
	"xops-admin/model"
)

type ListBugUseCase interface {
	GetDomainByClientID(id string) (*model.DomainClient, error)
	GetBugs(ctx context.Context, filter domain.ListBugFilter) (*domain.ListBugResponse, error)
}
