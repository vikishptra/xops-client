package routes_user

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	controller_list_bug "xops-admin/api/controller/user/list_bug"
	postgres "xops-admin/repo/repo_postgres"
	"xops-admin/usecase/user/list_bug"
)

func ListBugRoutes(app fiber.Router, db *gorm.DB, elasticSearch *elasticsearch.Client) {
	// init repository
	typeBugRepo := postgres.NewTypeBugRepo(db)
	listVulnRepo := postgres.NewListVulnerabilityRepo(db)
	listBugRepo := postgres.NewListBugRepository(db)
	ClientRepo := postgres.NewClientRepo(db)

	// init usecase
	typeBugUsecase := list_bug.NewListBug(typeBugRepo)

	listVulnUsecase := list_bug.NewListVulnerabilityUseCase(listVulnRepo)

	listBugUsecase := list_bug.NewListBugTableUseCase(listBugRepo, ClientRepo)
	// init handler
	typeBugHandler := controller_list_bug.NewTypeBugHandler(typeBugUsecase)

	listVuln := controller_list_bug.NewListVulnerabilityHandler(listVulnUsecase)

	listBugHandler := controller_list_bug.NewListBugTableHandler(listBugUsecase)

	r := app.Group("/type-bugs")
	r.Post("/", typeBugHandler.Create)      // create
	r.Get("/", typeBugHandler.List)         // list all (with optional search)
	r.Get("/:id", typeBugHandler.GetByID)   // get by id
	r.Put("/:id", typeBugHandler.Update)    // update
	r.Delete("/:id", typeBugHandler.Delete) // delete
	v := app.Group("/vulnerabilities")
	v.Post("/", listVuln.Create)
	v.Get("/", listVuln.List)
	v.Get("/:id", listVuln.GetByID)
	v.Put("/:id", listVuln.Update)
	v.Delete("/:id", listVuln.Delete)

	app.Get("/findings", listBugHandler.List)

}
