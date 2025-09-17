package domain_user

import (
	"time"

	"xops-admin/model"
	jwttoken "xops-admin/util/token_jwt"
)

type Verified2faResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	// Is2fa    bool   `json:"is_2fa"`
	Role         string `json:"role"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	// RefreshToken string    `json:"refresh_token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Verified2faRequest struct {
	Code string `json:"code" validate:"required"`
}
type SendOtpRequest struct {
	Email string `json:"email" validate:"required"`
}

type Verified2faCase interface {
	FindUserBYID(id string) (*model.User, error)
	ValidateRegister2FA(user *model.User) error
	UpdateUser(user *model.User, token string) error
	ValidateToken(token string, publicKey string) (*jwttoken.TokenDetails, error)
	ConvertVerified2faResponse(user *model.User, AccessTokentoken, RefreshToken, RoleName string) Verified2faResponse
	VerifyTOTP(code, key string) bool
	GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error)
	FindRoleName(user *model.User) string

	//v3
	UserVerifyOtp(idUser, code string, duration int64) (*model.User, error)
	SendOtpVerifedCode(user *model.User)
	FindEmail(email string) (*model.User, error)
}
