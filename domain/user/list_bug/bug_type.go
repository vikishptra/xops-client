// domain/user/list_bug/bug_type_usecase.go
package domain_listbug

import (
	"context"

	"xops-admin/model"
)

type BugTypeUseCase interface {
	Create(ctx context.Context, typeBug *model.TypeBug) error
	GetByID(ctx context.Context, id string) (*model.TypeBug, error)
	Update(ctx context.Context, typeBug *model.TypeBug) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, search string) ([]model.TypeBug, int64, error)
}
