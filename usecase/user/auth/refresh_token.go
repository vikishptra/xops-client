package auth

import (
	"time"

	"xops-admin/domain"
	domain_user "xops-admin/domain/user/auth"
	"xops-admin/model"
	jwttoken "xops-admin/util/token_jwt"
)

type RefreshTokenUseCase struct {
	refreshTokenRepo domain.UserRepository
}

func (r *RefreshTokenUseCase) FindUserBYID(id string) (*model.User, error) {
	user, err := r.refreshTokenRepo.FindUserBYID(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (l *RefreshTokenUseCase) SaveRefreshToken(token string, user *model.User) (*model.User, error) {
	user.RefreshToken = token
	if err := l.refreshTokenRepo.UpdateUser(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (u *RefreshTokenUseCase) GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error) {
	return jwttoken.GenerateTokenJwt(jwtTokenTime, userID, privateKey)
}
func (u *RefreshTokenUseCase) ValidateToken(token string, publicKey string) (*jwttoken.TokenDetails, error) {
	return jwttoken.ValidateToken(token, publicKey)
}

func NewRefreshTokenUseCase(refrehTokenRepo domain.UserRepository) domain_user.RefreshTokenUsecase {
	return &RefreshTokenUseCase{
		refreshTokenRepo: refrehTokenRepo,
	}
}
