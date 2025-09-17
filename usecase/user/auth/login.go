package auth

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"xops-admin/domain"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/model"
	util_encode "xops-admin/util/encode"
	jwttoken "xops-admin/util/token_jwt"
)

type LoginUserRepo struct {
	loginRepo domain.UserRepository
}

func (l *LoginUserRepo) LoginUser(email string) (*model.User, error) {
	user, err := l.loginRepo.FindUserBYEmail(email)
	if err != nil {
		return nil, err
	}
	if err == errorenum.DataNotFound {
		return nil, errorenum.FailedLogin
	}
	return user, nil

}

// func (l *LoginUserRepo) SaveRefreshToken(token string, user *model.User) (*model.User, error) {
// 	user.RefreshToken = token
// 	if err := l.loginRepo.UpdateUser(user); err != nil {
// 		return nil, err
// 	}
// 	return user, nil
// }

func (l *LoginUserRepo) ComparePasswordHash(user *model.User, password string) error {

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return errorenum.SomethingError
	}
	return nil
}

func (l *LoginUserRepo) ConvertUserToLoginResponse(user *model.User, accesToken string) domain_user_auth.LoginResponse {
	return domain_user_auth.LoginResponse{
		Is2fa:       user.IsTwoFA,
		AccessToken: accesToken,
	}
}

func (l *LoginUserRepo) IsUserVerified(u *model.User) error {
	if !u.IsVerified {
		return errorenum.FailedLogin
	}
	return nil
}

func (l *LoginUserRepo) GenerateTokenJwt(jwtTokenTime time.Duration, userID string, privateKey string) (*jwttoken.TokenDetails, error) {
	return jwttoken.GenerateTokenJwt(jwtTokenTime, userID, privateKey)
}

func (l *LoginUserRepo) SendOtpVerifedCode(user *model.User) {
	rand.Seed(time.Now().UnixNano())
	code := 100000 + rand.Intn(900000)
	verification_code := util_encode.Encode(strconv.Itoa(code))
	user.VerifiedCode = verification_code
	if err := l.loginRepo.UpdateUser(user); err != nil {
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
}

func NewLoginUseCase(loginRepo domain.UserRepository) domain_user_auth.LoginUseCase {
	return &LoginUserRepo{
		loginRepo: loginRepo,
	}
}
