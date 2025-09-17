package domain

import (
	"context"

	"xops-admin/model"
)

type TypeBugRepository interface {
	Create(ctx context.Context, typeBug *model.TypeBug) error
	GetByID(ctx context.Context, id string) (*model.TypeBug, error)
	Update(ctx context.Context, typeBug *model.TypeBug) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, search string) ([]model.TypeBug, int64, error)
}
