package auth

import (
	"xops-admin/domain"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
)

type RegisterUserRepo struct {
	UserRepo domain.UserRepository
}

func (r *RegisterUserRepo) ValidateCreateUserRequest(req *domain_user_auth.CreateUserWithClientRequest) error {
	if req.Email == "" {
		return errorenum.InvalidEmail
	}

	if req.IdRole == 3 {
		if req.LogoCompany == "" {
			return errorenum.LogoCompanyRequired
		}
		if req.CompanyName == "" {
			return errorenum.CompanyNameRequired
		}
		if req.StartDate.IsZero() {
			return errorenum.StartDateRequired
		}
		if req.EndDate.IsZero() {
			return errorenum.EndDateRequired
		}
		if req.StartDate.After(req.EndDate) {
			return errorenum.InvalidDateRange
		}
		if len(req.Domains) == 0 {
			return errorenum.DomainsRequired
		}

		for _, domain := range req.Domains {
			if domain == "" {
				return errorenum.InvalidDomainFormat
			}
		}
	}

	return nil
}

func (r *RegisterUserRepo) CreateUser(createUser *domain_user_auth.CreateUserWithClientRequest) (*domain_user_auth.CreateUserResponse, error) {
	if err := r.ValidateCreateUserRequest(createUser); err != nil {
		return nil, err
	}

	if err := r.UserRepo.CreateUser(createUser); err != nil {
		return nil, err
	}

	response := &domain_user_auth.CreateUserResponse{
		Email: createUser.Email,
	}

	if createUser.IdRole == 3 {
		response.CompanyLogo = createUser.LogoCompany
		response.CompanyName = createUser.CompanyName
		response.Domain = createUser.Domains
		response.StartDate = createUser.StartDate
		response.EndaDate = createUser.EndDate
	}

	return response, nil
}

func NewRegisterUseCase(UserRepo domain.UserRepository) domain_user_auth.RegisterUseCase {
	return &RegisterUserRepo{
		UserRepo: UserRepo,
	}
}
