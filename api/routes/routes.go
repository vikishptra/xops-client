package routes

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"xops-admin/api/routes/middleware"
	routes_user "xops-admin/api/routes/user"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
)

func SetUpRoutes(app *fiber.App, postgres *gorm.DB, elasticSearch *elasticsearch.Client) {

	routes := app.Group("/api")
	routes_user.AuthRoutes(routes, postgres)
	apiV1 := routes.Group("/v1", middleware.DeserializeUser)
	routes_user.OverviewRoutes(apiV1, postgres, elasticSearch)
	routes_user.SecurityChecklistRoutes(apiV1, postgres, elasticSearch)
	routes_user.ClientRoutes(apiV1, postgres, elasticSearch)
	routes_user.ListBugRoutes(apiV1, postgres, elasticSearch)

	routes.All("*", func(c *fiber.Ctx) error {
		path := c.Path()
		message := string(errorenum.InvalidRoutes) + " " + path
		payload := payload.NewErrorResponse(message)
		return c.Status(fiber.StatusBadRequest).JSON(payload)
	})

}
