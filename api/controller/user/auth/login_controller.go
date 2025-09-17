package controller_user

import (
	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	"xops-admin/model"
)

type Login struct {
	loginUseCase domain_user_auth.LoginUseCase
}

func NewLoginController(loginUsecase domain_user_auth.LoginUseCase) *Login {
	return &Login{
		loginUseCase: loginUsecase,
	}
}
func (l *Login) LoginUserControlller(c *fiber.Ctx) error {
	var input domain_user_auth.LoginRequest
	var response payload.Response

	if err := c.BodyParser(&input); err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	if err := model.ValidateStruct(input); len(err) > 0 {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	user, err := l.loginUseCase.LoginUser(input.Email)
	if err == errorenum.DataNotFound {
		response = payload.NewErrorResponse(errorenum.FailedLogin)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	// if err := l.loginUseCase.IsUserVerified(user); err != nil {
	// 	response = payload.NewErrorResponse(err)
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }
	if !user.IsVerified {
		response := payload.NewErrorResponse(errorenum.FailedLogin)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	if err := l.loginUseCase.ComparePasswordHash(user, input.Password); err != nil {
		response = payload.NewErrorResponse(errorenum.FailedLogin)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	//send otp
	l.loginUseCase.SendOtpVerifedCode(user)
	config, _ := config.LoadConfig(".")

	accessTokenDetails, err := l.loginUseCase.GenerateTokenJwt(config.AccessTokenExpiresIn, user.Id, config.AccessTokenPrivateKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// refreshTokenDetails, err := l.loginUseCase.GenerateTokenJwt(config.RefreshTokenExpiresIn, user.Id, config.RefreshTokenPrivateKey)
	// if err != nil {
	// 	response = payload.NewErrorResponse(err.Error())
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }
	// user, err = l.loginUseCase.SaveRefreshToken(*refreshTokenDetails.Token, user)
	// if err != nil {
	// 	response = payload.NewErrorResponse(err)
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *accessTokenDetails.Token,
		Path:     "/",
		MaxAge:   config.AccessTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   config.RefreshTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "logged_in",
		Value:    "true",
		Path:     "/",
		MaxAge:   config.AccessTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
	})

	responseLoginResponse := l.loginUseCase.ConvertUserToLoginResponse(user, *accessTokenDetails.Token)
	response = payload.NewSuccessResponse(responseLoginResponse, errorenum.SuccessLogin)
	return c.Status(fiber.StatusOK).JSON(response)
}
