package controller_list_bug

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	"xops-admin/domain"
	domain_listbug "xops-admin/domain/user/list_bug"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	util_jwttoken "xops-admin/util/token_jwt"
)

type ListBugTableHandler struct {
	usecase domain_listbug.ListBugUseCase
}

func NewListBugTableHandler(u domain_listbug.ListBugUseCase) *ListBugTableHandler {
	return &ListBugTableHandler{usecase: u}
}

func (h *ListBugTableHandler) List(c *fiber.Ctx) error {
	var response payload.Response

	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	nameDomain, err := h.usecase.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// Parse limit with default
	limit := 1
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// Clean up parameters - detect malformed URL
	lastID := c.QueryInt("last_id")
	lastTime := c.Query("last_time")
	direction := c.Query("direction")
	convert := strings.TrimSpace(c.Query("convert")) // NEW: Parse convert parameter

	// Set defaults
	if direction == "" {
		direction = "next"
	}

	sortBy := strings.TrimSpace(c.Query("sort_by"))
	if sortBy == "" {
		sortBy = "created_at"
	}

	sortOrder := strings.TrimSpace(c.Query("sort_order"))
	if sortOrder == "newest" || sortOrder == "" {
		sortOrder = "desc"
	}
	if sortOrder == "oldest" {
		sortOrder = "asc"
	}

	// Parse query parameters manually to avoid struct tag issues
	filter := domain.ListBugFilter{
		// Pagination parameters
		Limit:     limit,
		LastID:    lastID,
		LastTime:  lastTime,
		Direction: direction,

		// Filter parameters
		Severity:   strings.TrimSpace(c.Query("severity")),
		Status:     strings.TrimSpace(c.Query("status")),
		FlagDomain: nameDomain.Domain,

		// Search parameter
		Search: strings.TrimSpace(c.Query("search")),

		// Sort parameters
		SortBy:    sortBy,
		SortOrder: sortOrder,

		// Convert parameter
		Convert: convert, // NEW: Add convert parameter
	}

	// Call usecase
	result, err := h.usecase.GetBugs(context.TODO(), filter)
	if err != nil {
		fmt.Printf("Error from usecase: %v\n", err)
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Handle CSV download
	if convert == "csv" {
		if result.CSVData == "" {
			response = payload.NewErrorResponse("No CSV data generated")
			return c.Status(fiber.StatusInternalServerError).JSON(response)
		}

		// Generate filename with timestamp
		now := time.Now()
		filename := fmt.Sprintf("bug_report_%s.csv", now.Format("20060102_150405"))

		// Set headers for CSV download
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Set("Pragma", "no-cache")
		c.Set("Expires", "0")

		// Return CSV content directly
		return c.SendString(result.CSVData)
	}

	// Regular JSON response for non-CSV requests
	result.Success = true
	result.Message = errorenum.OKSuccess
	return c.Status(fiber.StatusOK).JSON(result)
}
