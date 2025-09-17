package postgres

import (
	"gorm.io/gorm"

	"xops-admin/domain"
	"xops-admin/helper/errorenum"
	"xops-admin/model"
)

type RoleRepo struct {
	db *gorm.DB
}

func (r *RoleRepo) CreateRole(role *model.Role) error {
	var maxID uint
	if err := r.db.Model(&model.Role{}).Select("COALESCE(MAX(id), 0)").Row().Scan(&maxID); err != nil {
		return err
	}
	role.Id = int(maxID) + 1
	result := r.db.Create(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
func (r *RoleRepo) FindAllRoles() ([]*model.Role, error) {
	var roles []*model.Role
	result := r.db.Find(&roles)
	if result.Error != nil {
		return nil, result.Error
	}
	return roles, nil
}

func (u *RoleRepo) FindRoleBYName(name string) (*model.Role, error) {
	var role model.Role
	if err := u.db.First(&role, "name_role = ?", name); err.RowsAffected == 0 {
		return nil, errorenum.DataNotFound
	}
	return &role, nil
}

func (u *RoleRepo) FindRoleBYID(id int) (*model.Role, error) {
	var role model.Role
	if err := u.db.First(&role, "id = ?", id); err.RowsAffected == 0 {
		return nil, errorenum.DataNotFound
	}
	return &role, nil
}

func (r *RoleRepo) DeleteRole(id int) error {
	result := r.db.Delete(&model.Role{}, id)
	if result.Error != nil {
		return errorenum.SomethingError
	}
	return nil
}
func (r *RoleRepo) UpdateRole(role *model.Role) error {
	result := r.db.Save(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func NewRoleRepo(db *gorm.DB) domain.RoleRepository {
	return &RoleRepo{
		db: db,
	}
}
