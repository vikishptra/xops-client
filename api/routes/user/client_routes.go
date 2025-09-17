package routes_user

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	controller_user_client "xops-admin/api/controller/user/client"
	postgres "xops-admin/repo/repo_postgres"
	usecase_client "xops-admin/usecase/user/client"
)

func ClientRoutes(app fiber.Router, db *gorm.DB, elasticSearch *elasticsearch.Client) {
	UserRepo := postgres.NewUserRepo(db)
	ClientRepo := postgres.NewClientRepo(db)

	clientUsecase := usecase_client.NewClientUseCase(ClientRepo, UserRepo)
	clientController := controller_user_client.NewClientUserHandler(clientUsecase, elasticSearch)

	app.Post("/clients", clientController.CreateClient)
	app.Get("/clients", clientController.GetDomainClient)
}
