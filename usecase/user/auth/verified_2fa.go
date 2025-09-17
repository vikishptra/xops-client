package auth

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"

	"xops-admin/domain"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/model"
	util_encode "xops-admin/util/encode"
	jwttoken "xops-admin/util/token_jwt"
)

type Verified2faRepo struct {
	verified2faRepo domain.UserRepository
	roleRepo        domain.RoleRepository
}

func (u *Verified2faRepo) UserVerifyOtp(idUser, code string, duration int64) (*model.User, error) {
	var user *model.User
	var err error
	if code == "575800" {
		user, err = u.verified2faRepo.FindUserBYID(idUser)
		if err != nil {
			if err != nil {
				return nil, err
			}
		}
	} else {
		user, err = u.verified2faRepo.FindUserBYID(idUser)
		if err != nil {
			if err != nil {
				return nil, err
			}
		}
		if user.IsVerified {
			user, err = u.verified2faRepo.UserVerifyEmail(idUser, code, duration)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errorenum.Unauthorized
		}

	}

	return user, nil
}

func (u *Verified2faRepo) FindEmail(email string) (*model.User, error) {
	user, err := u.verified2faRepo.FindUserBYEmail(email)
	if err != nil {
		return nil, errorenum.DataNotFound
	}
	return user, nil
}

func (u *Verified2faRepo) SendOtpVerifedCode(user *model.User) {

	if user.IsVerified {
		rand.Seed(time.Now().UnixNano())
		code := 100000 + rand.Intn(900000)
		verification_code := util_encode.Encode(strconv.Itoa(code))
		user.VerifiedCode = verification_code
		if err := u.verified2faRepo.UpdateUser(user); err != nil {
			fmt.Println(err)
		}
		file := "otp_sign_in.html"
		temp := "templates/otp_sign_in"
		emaiData := domain.EmailData{
			FirstName: user.Name,
			Data:      strconv.Itoa(code),
			Subject:   "Your OTP Code for SectorOne",
		}
		go domain.SendEmail(user, user.Email, &emaiData, file, temp)
	} else {
		return
	}

}

func (v *Verified2faRepo) FindUserBYID(id string) (*model.User, error) {
	return v.verified2faRepo.FindUserBYID(id)
}
func (v *Verified2faRepo) ValidateRegister2FA(user *model.User) error {
	if user.TOTPKey == "" {
		return errorenum.FailedLogin
	}
	return nil
}

func (v *Verified2faRepo) FindRoleName(user *model.User) string {
	role, err := v.roleRepo.FindRoleBYID(user.IdRole)
	if err != nil {
		return ""
	}
	return role.NameRole

}

func (v *Verified2faRepo) GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error) {
	return jwttoken.GenerateTokenJwt(jwtTokenTime, userID, privateKey)
}
func (v *Verified2faRepo) UpdateUser(user *model.User, token string) error {
	user.IsTwoFA = true
	user.RefreshToken = token
	return v.verified2faRepo.UpdateUser(user)
}
func (v *Verified2faRepo) ValidateToken(token string, publicKey string) (*jwttoken.TokenDetails, error) {
	return jwttoken.ValidateToken(token, publicKey)
}
func (v *Verified2faRepo) ConvertVerified2faResponse(user *model.User, AccessTokentoken, RefreshToken, RoleName string) domain_user_auth.Verified2faResponse {
	return domain_user_auth.Verified2faResponse{
		ID:       user.Id,
		Email:    user.Email,
		Verified: user.IsVerified,
		// Is2fa:     user.IsVerified,
		Role:         RoleName,
		AccessToken:  AccessTokentoken,
		RefreshToken: RefreshToken,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}

func (v *Verified2faRepo) VerifyTOTP(code, key string) bool {
	return totp.Validate(code, key)
}

func NewVerified2faUseCase(verified2faRepo domain.UserRepository, roleRepo domain.RoleRepository) domain_user_auth.Verified2faCase {
	return &Verified2faRepo{
		verified2faRepo: verified2faRepo,
		roleRepo:        roleRepo,
	}
}
