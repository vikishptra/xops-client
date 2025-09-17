package domain

import (
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/model"
)

type UserRepository interface {
	CreateUser(req *domain_user_auth.CreateUserWithClientRequest) error
	FindUserBYID(id string) (*model.User, error)
	FindUserBYEmail(email string) (*model.User, error)
	UpdateUser(user *model.User) error
	DeleteUser(id string) error
	FindUserBYName(name string) (*model.User, error)
	UserVerifyEmail(idUser, code string, duration int64) (*model.User, error)
}
