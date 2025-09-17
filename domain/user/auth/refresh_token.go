package domain_user

import (
	"time"

	"xops-admin/model"
	jwttoken "xops-admin/util/token_jwt"
)

type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenUsecase interface {
	FindUserBYID(id string) (*model.User, error)
	ValidateToken(token string, publicKey string) (*jwttoken.TokenDetails, error)
	GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error)
	SaveRefreshToken(token string, user *model.User) (*model.User, error)
}
