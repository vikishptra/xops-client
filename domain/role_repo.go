package domain

import "xops-admin/model"

type RoleRepository interface {
	CreateRole(role *model.Role) error
	FindRoleBYName(name string) (*model.Role, error)
	FindRoleBYID(id int) (*model.Role, error)
	FindAllRoles() ([]*model.Role, error)
	DeleteRole(id int) error
	UpdateRole(role *model.Role) error
}
