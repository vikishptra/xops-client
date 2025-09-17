package domain_user

import (
	"time"

	"xops-admin/model"
	jwttoken "xops-admin/util/token_jwt"
)

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	Is2fa       bool   `json:"is_2fa"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginUseCase interface {
	LoginUser(email string) (*model.User, error)
	ConvertUserToLoginResponse(user *model.User, accesToken string) LoginResponse
	GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error)
	ComparePasswordHash(user *model.User, password string) error
	IsUserVerified(u *model.User) error
	SendOtpVerifedCode(user *model.User)
	// SaveRefreshToken(token string, user *model.User) (*model.User, error)
}
