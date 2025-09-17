package middleware

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	"xops-admin/model"
	token "xops-admin/util/token_jwt"
)

func MiddlewareApiKey(c *fiber.Ctx) error {
	var response payload.Response
	_, err := net.Dial("tcp", "www.google.com:80")
	if err != nil {
		response = payload.NewErrorResponse("Tidak ada koneksi internet")
		return c.Status(fiber.StatusServiceUnavailable).JSON(response)
	}
	return c.Next()
}

func DeserializeUser(c *fiber.Ctx) error {
	var access_token string
	var response payload.Response
	_, err := net.Dial("tcp", "www.google.com:80")
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).SendString("Tidak ada koneksi internet.")
	}
	authorization := c.Get("Authorization")
	// refresh_token := c.Cookies("refresh_token")
	if strings.HasPrefix(authorization, "Bearer ") {
		access_token = strings.TrimPrefix(authorization, "Bearer ")
	}
	if access_token == "" {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	loadconfig, _ := config.LoadConfig(".")

	tokenClaims, err := token.ValidateToken(access_token, loadconfig.AccessTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusForbidden).JSON(response)
	}
	userId := tokenClaims.UserID
	var user model.User

	refresh_token := c.Cookies("refresh_token")
	access_token_cookies := c.Cookies("access_token")

	if err := config.DB.First(&user, "id = ?", userId); err.RowsAffected < 0 {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if user.IdRole != 1 && user.IdRole != 2 {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if user.RefreshToken != refresh_token || access_token_cookies != access_token {
		response = payload.NewErrorResponse(errorenum.Unauthorized)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if !user.IsVerified {
		response = payload.NewErrorResponse(errorenum.Forbidden)
		return c.Status(fiber.StatusForbidden).JSON(response)
	}
	if err := config.DB.First(&user, "id = ?", userId); err.RowsAffected < 0 {
		response = payload.NewErrorResponse(errorenum.Forbidden)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	c.Locals("user", model.ConvertUser(&user))
	c.Locals("access_token_uuid", tokenClaims.TokenUuid)

	return c.Next()
}
func GetPublicIP(c *fiber.Ctx) string {
	if ip := c.Get("X-Forwarded-For"); ip != "" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	if ip := c.Get("X-Real-IP"); ip != "" {
		return ip
	}

	return c.IP()
}
func RateLimitApi(windowSize time.Duration, requestLimit int) fiber.Handler {
	ipRequests := make(map[string]int)
	mutex := sync.RWMutex{}
	var response payload.Response

	go func() {
		for {
			time.Sleep(windowSize)
			mutex.Lock()
			ipRequests = make(map[string]int)
			mutex.Unlock()
		}
	}()

	return func(c *fiber.Ctx) error {
		apiKey := c.Get("api-key")

		if apiKey == "dev-sector" {
			return c.Next()
		}

		ip := GetPublicIP(c)

		mutex.RLock()
		if count, exists := ipRequests[ip]; exists && count >= requestLimit {
			mutex.RUnlock()
			response = payload.NewErrorResponse(errorenum.RateLimit)
			return c.Status(fiber.StatusTooManyRequests).JSON(response)
		}
		mutex.RUnlock()

		mutex.Lock()
		ipRequests[ip]++
		mutex.Unlock()

		return c.Next()
	}
}
