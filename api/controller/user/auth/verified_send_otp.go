package controller_user

import (
	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_user_auth "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	"xops-admin/model"
)

func NewVerifiedOtPfaController(verified2faUseCase domain_user_auth.Verified2faCase) *Verified2fa {
	return &Verified2fa{
		verified2faUseCase: verified2faUseCase,
	}
}
func (v *Verified2fa) SendOtpVerifedCode(c *fiber.Ctx) error {
	var input domain_user_auth.SendOtpRequest
	var response payload.Response
	var user *model.User
	var err error

	loadconfig, _ := config.LoadConfig(".")
	access_token_cookies := c.Cookies("access_token")

	if access_token_cookies == "" && input.Email != "" {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if access_token_cookies != "" {
		tokenClaims, err := v.verified2faUseCase.ValidateToken(access_token_cookies, loadconfig.AccessTokenPublicKey)
		if err != nil {
			response = payload.NewErrorResponse(err.Error())
			return c.Status(fiber.StatusUnauthorized).JSON(response)
		}
		user, err = v.verified2faUseCase.FindUserBYID(tokenClaims.UserID)
		if err != nil {
			response = payload.NewErrorResponse(errorenum.Unauthorized)
			return c.Status(fiber.StatusUnauthorized).JSON(response)
		}
	} else {
		if err := c.BodyParser(&input); err != nil {
			response = payload.NewErrorResponse(err.Error())
			return c.Status(fiber.StatusBadRequest).JSON(response)
		}
		if err := model.ValidateStruct(input); len(err) > 0 {
			response = payload.NewErrorResponse(err)
			return c.Status(fiber.StatusBadRequest).JSON(response)
		}
		user, err = v.verified2faUseCase.FindEmail(input.Email)
		if err != nil {
			response = payload.NewErrorResponse(errorenum.SomethingError)
			return c.Status(fiber.StatusUnauthorized).JSON(response)
		}
	}

	v.verified2faUseCase.SendOtpVerifedCode(user)
	response = payload.NewSuccessResponse(nil, errorenum.SendOtp)
	return c.Status(fiber.StatusOK).JSON(response)

}
func (v *Verified2fa) VerifiedOtpControlller(c *fiber.Ctx) error {
	var input domain_user_auth.Verified2faRequest
	var response payload.Response
	loadconfig, _ := config.LoadConfig(".")
	access_token_cookies := c.Cookies("access_token")

	if access_token_cookies == "" {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if err := c.BodyParser(&input); err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	if err := model.ValidateStruct(input); len(err) > 0 {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	tokenClaims, err := v.verified2faUseCase.ValidateToken(access_token_cookies, loadconfig.AccessTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	user, err := v.verified2faUseCase.FindUserBYID(tokenClaims.UserID)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	// if err := v.verified2faUseCase.ValidateRegister2FA(user); err != nil {
	// 	response = payload.NewErrorResponse(err)
	// 	return c.Status(fiber.StatusUnauthorized).JSON(response)
	// }
	// verifiedTOTP := v.verified2faUseCase.VerifyTOTP(input.Code, user.TOTPKey)
	// if !verifiedTOTP {
	// 	response = payload.NewErrorResponse(errorenum.CodeTidakValid)
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }
	userData, err := v.verified2faUseCase.UserVerifyOtp(user.Id, input.Code, 5)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	refreshTokenDetails, err := v.verified2faUseCase.GenerateTokenJwt(loadconfig.RefreshTokenExpiresIn, userData.Id, loadconfig.RefreshTokenPrivateKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	// user, err = l.loginUseCase.SaveRefreshToken(*refreshTokenDetails.Token, user)
	// if err != nil {
	// 	response = payload.NewErrorResponse(err)
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }
	if err := v.verified2faUseCase.UpdateUser(userData, *refreshTokenDetails.Token); err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	// ip := c.IP()
	// userAgent := c.Get("User-Agent")
	// if err := v.activityLogUseCase.CreateActivityLog(userData.Id, ip, "Login", userAgent); err != nil {
	// 	response = payload.NewErrorResponse(err)
	// 	return c.Status(fiber.StatusBadRequest).JSON(response)
	// }
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    *refreshTokenDetails.Token,
		Path:     "/",
		MaxAge:   loadconfig.RefreshTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
	})
	roleName := v.verified2faUseCase.FindRoleName(userData)
	resultResponse := v.verified2faUseCase.ConvertVerified2faResponse(userData, access_token_cookies, *refreshTokenDetails.Token, roleName)
	response = payload.NewSuccessResponse(resultResponse, errorenum.SuccessOtp)
	return c.Status(fiber.StatusOK).JSON(response)
}
