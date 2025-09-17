package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"gorm.io/gorm"

	"xops-admin/api/routes"
	"xops-admin/config"
)

func main() {

	fmt.Println("Hello SibertrenID")
	loadConfig, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalln("Failed to load environment variables! \n", err.Error())
	}
	postgresDB := config.ConnectionToMPostGresDB(&loadConfig)
	elastic := config.ConnectionToElastic()
	config.ConnectRedis(&loadConfig)
	SetUpServer(postgresDB, elastic, ":8005")

}

func SetUpServer(postgresDB *gorm.DB, elastic *elasticsearch.Client, port string) {
	app := fiber.New()
	app.Use(logger.New())
	//konfigurasi security
	app.Use(helmet.New(helmet.Config{
		XSSProtection:             "1; mode=block",
		ContentTypeNosniff:        "nosniff",
		XFrameOptions:             "SAMEORIGIN",
		ReferrerPolicy:            "no-referrer",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginResourcePolicy: "same-origin",
		OriginAgentCluster:        "?1",
		XDNSPrefetchControl:       "off",
		XDownloadOptions:          "noopen",
		XPermittedCrossDomain:     "none",
		ContentSecurityPolicy:     "default-src 'self'",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,https://localhost:3000,https://xops-api.sector.co.id,http://xops-api.sector.co.id,https://xops.sector.co.id, https://xops-staging.sector.co.id, https://xopsclient-api.sector.co.id,http://xopsclient-api.sector.co.i",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization, Set-Cookie, api-key",
		AllowMethods:     "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS",
		AllowCredentials: true,
	}))
	app.Use(func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		if strings.HasPrefix(origin, "moz-extension://") {
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
			c.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, Set-Cookie")
			c.Set("Access-Control-Allow-Credentials", "true")
			c.Set("Connection", "Keep-Alive")
			c.Set("Keep-Alive", "timeout=500, max=20")

			if c.Method() == "OPTIONS" {
				return c.SendStatus(fiber.StatusOK)
			}
		}
		return c.Next()
	})
	app.Static("/static", "./public/static")
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("Hello World Server Running V3.3.2 🚀")
	})
	routes.SetUpRoutes(app, postgresDB, elastic)
	if err := app.Listen(port); err != nil {
		panic(err)
	}
}
