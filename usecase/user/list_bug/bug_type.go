// usecase/list_bug_repo.go
package list_bug

import (
	"context"

	"xops-admin/domain"
	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/model"
)

type ListBugRepo struct {
	listBug domain.TypeBugRepository
}

func NewListBug(listBug domain.TypeBugRepository) domain_listbug.BugTypeUseCase {
	return &ListBugRepo{listBug: listBug}
}

func (r *ListBugRepo) Create(ctx context.Context, typeBug *model.TypeBug) error {
	return r.listBug.Create(ctx, typeBug)
}

func (r *ListBugRepo) GetByID(ctx context.Context, id string) (*model.TypeBug, error) {
	return r.listBug.GetByID(ctx, id)
}

func (r *ListBugRepo) Update(ctx context.Context, typeBug *model.TypeBug) error {
	return r.listBug.Update(ctx, typeBug)
}

func (r *ListBugRepo) Delete(ctx context.Context, id string) error {
	return r.listBug.Delete(ctx, id)
}

func (r *ListBugRepo) List(ctx context.Context, search string) ([]model.TypeBug, int64, error) {
	return r.listBug.List(ctx, search)
}
