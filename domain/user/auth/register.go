package domain_user

import (
	"time"
)

type CreateUserResponse struct {
	Email       string    `json:"email"`
	CompanyLogo string    `json:"company_logo"`
	CompanyName string    `json:"company_name"`
	Domain      []string  `json:"domain"`
	StartDate   time.Time `json:"start_date"`
	EndaDate    time.Time `json:"enda_date"`
}
type CreateUserWithClientRequest struct {
	// User fields
	Email        string `json:"email"`
	Password     string `json:"password"`
	IdRole       int    `json:"id_role"`
	IsVerified   bool   `json:"is_verified"`
	IsTwoFA      bool   `json:"is_2fa"`
	VerifiedCode string `json:"verified_code"`
	TOTPKey      string `json:"totp_key"`
	RefreshToken string `json:"refresh_token"`
	ApiKey       string `json:"api_key"`

	// Client fields
	LogoCompany string    `json:"logo_company"`
	CompanyName string    `json:"company_name"`
	StartDate   time.Time `json:"start_date"`
	EndDate     time.Time `json:"end_date"`

	// Domain fields
	Domains []string `json:"domains"`
}

type RegisterUseCase interface {
	CreateUser(createUser *CreateUserWithClientRequest) (*CreateUserResponse, error)
	// SaveRefreshToken(token string, user *model.User) (*model.User, error)
}
