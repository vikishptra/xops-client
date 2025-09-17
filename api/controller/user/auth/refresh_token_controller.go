package controller_user

import (
	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_user "xops-admin/domain/user/auth"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
)

type RefreshToken struct {
	refreshTokenUsecase domain_user.RefreshTokenUsecase
}

func NewRefreshTokenController(refreshTokenUsecase domain_user.RefreshTokenUsecase) *RefreshToken {
	return &RefreshToken{
		refreshTokenUsecase: refreshTokenUsecase,
	}
}

func (r *RefreshToken) RefreshTokenController(c *fiber.Ctx) error {
	var response payload.Response

	//cek validasi di cookie refresh_tokenya
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	if refresh_token == "" {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	tokenClaims, err := r.refreshTokenUsecase.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	user, err := r.refreshTokenUsecase.FindUserBYID(tokenClaims.UserID)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	if user.RefreshToken != refresh_token {
		response = payload.NewErrorResponse(errorenum.Forbidden)
		return c.Status(fiber.StatusForbidden).JSON(response)
	}

	//dapatin lagi acccess keynya
	accesToken, err := r.refreshTokenUsecase.GenerateTokenJwt(loadconfig.AccessTokenExpiresIn, user.Id, loadconfig.AccessTokenPrivateKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}
	tokenAcces := accesToken.Token

	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    *tokenAcces,
		Path:     "/",
		MaxAge:   loadconfig.AccessTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: true,
		SameSite: "None",
	})

	c.Cookie(&fiber.Cookie{
		Name:     "logged_in",
		Value:    "true",
		Path:     "/",
		MaxAge:   loadconfig.AccessTokenMaxAge * 60,
		Secure:   true,
		HTTPOnly: false,
		SameSite: "None",
	})

	response = payload.NewSuccessResponse(fiber.Map{"access_token": tokenAcces}, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)

}
