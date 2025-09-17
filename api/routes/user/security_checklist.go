package routes_user

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	controller_security_checklist "xops-admin/api/controller/user/security_checklist"
	postgres_1 "xops-admin/repo"
	"xops-admin/repo/repo_elasticsearch"
	postgres "xops-admin/repo/repo_postgres"
	"xops-admin/usecase/user/security_checklist"
)

func SecurityChecklistRoutes(app fiber.Router, db *gorm.DB, elasticSearch *elasticsearch.Client) {
	SecurityChecklistRepoRedis := repo_elasticsearch.NewSecurityCheklistRepo(elasticSearch)
	ClientRepo := postgres.NewClientRepo(db)
	listVulnRepo := postgres.NewListVulnerabilityRepo(db)
	bulkDataSecurityRepo := postgres_1.NewBulkUpdateSecurityChecklistRepository(db, elasticSearch)

	OverviewUserUseCase := security_checklist.NewSecurityChecklist(SecurityChecklistRepoRedis, ClientRepo, listVulnRepo, bulkDataSecurityRepo)
	SecurityChecklistController := controller_security_checklist.NewSecurityCheklistHandler(OverviewUserUseCase)

	app_security_checklist := app.Group("/security-checklist")
	app_security_checklist.Get("/total-findings", SecurityChecklistController.GetTotalFindingsController)
	app_security_checklist.Get("/checklist-table", SecurityChecklistController.GetSecurityChecklistTableController)
	app_security_checklist.Get("/list-url", SecurityChecklistController.GetURLListController)
	app_security_checklist.Get("/list-vulnerabilities", SecurityChecklistController.ListVulnController)
	app_security_checklist.Get("/total-bug-status", SecurityChecklistController.GetTotalBugStatusListController)
	app_security_checklist.Get("/checklist-table/:id", SecurityChecklistController.GetSecurityChecklistTableDetailIdController)

	app_security_checklist.Post("/checklist-table/bulk-update", SecurityChecklistController.BulkUpdate)
}
