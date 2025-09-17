package postgres

import (
	"context"

	"gorm.io/gorm"

	"xops-admin/domain"
	"xops-admin/model"
	util_uuid "xops-admin/util/uuid"
)

type TypeBugRepo struct {
	db *gorm.DB
}

func NewTypeBugRepo(db *gorm.DB) domain.TypeBugRepository {
	return &TypeBugRepo{db: db}
}

func (r *TypeBugRepo) Create(ctx context.Context, typeBug *model.TypeBug) error {
	typeBug.ID = util_uuid.GenerateID()
	return r.db.WithContext(ctx).Create(typeBug).Error
}

func (r *TypeBugRepo) GetByID(ctx context.Context, id string) (*model.TypeBug, error) {
	var typeBug model.TypeBug
	if err := r.db.WithContext(ctx).First(&typeBug, id).Error; err != nil {
		return nil, err
	}
	return &typeBug, nil
}

func (r *TypeBugRepo) Update(ctx context.Context, typeBug *model.TypeBug) error {
	return r.db.WithContext(ctx).Save(typeBug).Error
}
func (r *TypeBugRepo) Delete(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&model.TypeBug{}).Error
}

func (r *TypeBugRepo) List(ctx context.Context, search string) ([]model.TypeBug, int64, error) {
	var results []model.TypeBug
	var total int64

	query := r.db.WithContext(ctx).Model(&model.TypeBug{})

	if search != "" {
		query = query.Where("name ILIKE ?", "%"+search+"%")
	}

	// hitung total
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// ambil semua data tanpa pagination
	if err := query.Order("created_at DESC").Find(&results).Error; err != nil {
		return nil, 0, err
	}

	return results, total, nil
}
