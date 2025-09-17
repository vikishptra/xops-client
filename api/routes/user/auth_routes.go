package routes_user

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	controller_user_auth "xops-admin/api/controller/user/auth"
	"xops-admin/api/routes/middleware"
	postgres "xops-admin/repo/repo_postgres"
	usecase_user "xops-admin/usecase/user/auth"
)

func AuthRoutes(app fiber.Router, db *gorm.DB) {
	UserRepo := postgres.NewUserRepo(db)
	RoleRepo := postgres.NewRoleRepo(db)

	//

	//

	//register 2fa

	///
	verified2faUsecase := usecase_user.NewVerified2faUseCase(UserRepo, RoleRepo)
	verified2faController := controller_user_auth.NewVerified2faController(verified2faUsecase)
	LoginUseCase := usecase_user.NewLoginUseCase(UserRepo)
	LoginController := controller_user_auth.NewLoginController(LoginUseCase)

	refreshTokenUsecase := usecase_user.NewRefreshTokenUseCase(UserRepo)
	refreshTokenControler := controller_user_auth.NewRefreshTokenController(refreshTokenUsecase)
	///
	app.Post("/v1/verify-otp", middleware.RateLimitApi(15*time.Minute, 5), verified2faController.VerifiedOtpControlller)
	app.Post("/v1/send-otp", middleware.RateLimitApi(15*time.Minute, 5), verified2faController.SendOtpVerifedCode)
	app.Post("/refresh-token", refreshTokenControler.RefreshTokenController)

	apiAuthGroup := app.Group("/auth", middleware.MiddlewareApiKey)
	apiAuthGroup.Post("/login", middleware.RateLimitApi(15*time.Minute, 5), LoginController.LoginUserControlller)

}
