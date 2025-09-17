package routes_user

import (
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	controller_overview "xops-admin/api/controller/user/overview"
	"xops-admin/repo/repo_elasticsearch"
	postgres "xops-admin/repo/repo_postgres"
	"xops-admin/usecase/user/overview"
)

func OverviewRoutes(app fiber.Router, db *gorm.DB, elasticSearch *elasticsearch.Client) {
	OverviewRepoRedis := repo_elasticsearch.NewBugDiscoveryTimelineRepo(elasticSearch)
	ClientRepo := postgres.NewClientRepo(db)
	OverviewUserUseCase := overview.NewBugDiscoveryTimeline(OverviewRepoRedis, ClientRepo)
	BugDiscoveryTimelineController := controller_overview.NewBugDiscoveryTimelineHandler(OverviewUserUseCase)

	app.Get("/discovery-timeline", BugDiscoveryTimelineController.BugDiscoveryTimelineController)
	app.Get("/severity-distribution", BugDiscoveryTimelineController.BugSeverityDistributionController)
	app.Get("/status-distribution", BugDiscoveryTimelineController.BugStatusDistributionController)
	app.Get("/validation-distribution", BugDiscoveryTimelineController.BugValidationDistributionController)

	app.Get("/host-exposure", BugDiscoveryTimelineController.HostBugsExposureController)
	app.Get("/pentester-activity", BugDiscoveryTimelineController.PentestersActivityStatsController)

	app.Get("/bug-type-frequency", BugDiscoveryTimelineController.BugTypeFrequencyController)

	app.Get("/total-finding-discovered", BugDiscoveryTimelineController.GetTotalFindingsWithTrendController)

	app.Get("/pentesters-effectiveness", BugDiscoveryTimelineController.PentesterEffectivenessController)

	app.Get("/log-activity", BugDiscoveryTimelineController.GetLogActivityController)

}
