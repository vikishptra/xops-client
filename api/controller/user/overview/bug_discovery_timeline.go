package controller_overview

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_overview "xops-admin/domain/user/overview"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	util_jwttoken "xops-admin/util/token_jwt"
)

type BugDiscoveryTimelineHandler struct {
	service domain_overview.BugDiscoveryTimelineUseCase
}

func NewBugDiscoveryTimelineHandler(service domain_overview.BugDiscoveryTimelineUseCase) *BugDiscoveryTimelineHandler {
	return &BugDiscoveryTimelineHandler{
		service: service,
	}
}

// Existing endpoint - Chart 1: Vulnerability Timeline
func (l *BugDiscoveryTimelineHandler) BugDiscoveryTimelineController(c *fiber.Ctx) error {
	var response payload.Response
	period := c.QueryInt("period")
	filter := c.Query("filter")
	if period == 0 {
		period = 30
	}
	if filter == "all_severity" {
		filter = ""
	}
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	chartData, err := l.service.GetVulnerabilityChart(context.TODO(), period, nameDomain.Domain, filter)
	if err != nil || chartData == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(chartData, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 2 - Bug Severity Distribution
func (l *BugDiscoveryTimelineHandler) BugSeverityDistributionController(c *fiber.Ctx) error {
	var response payload.Response

	period := c.QueryInt("period")
	status := c.Query("status")
	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if status == "all_severity" {
		status = ""
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	distributions, err := l.service.GetBugSeverityDistribution(context.TODO(), nameDomain.Domain, period, status)
	if err != nil || distributions == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(distributions, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 2 - Bug Status Distribution
func (l *BugDiscoveryTimelineHandler) BugStatusDistributionController(c *fiber.Ctx) error {
	var response payload.Response

	period := c.QueryInt("period")
	status := c.Query("status")
	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if status == "all_status" {
		status = ""
	}
	distributions, err := l.service.GetBugStatusDistribution(context.TODO(), nameDomain.Domain, period, status)
	if err != nil || distributions == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(distributions, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 2 - Bug Validation Distribution
func (l *BugDiscoveryTimelineHandler) BugValidationDistributionController(c *fiber.Ctx) error {
	var response payload.Response

	period := c.QueryInt("period")
	status := c.Query("status")
	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	if status == "all_validation" {
		status = ""
	}
	distributions, err := l.service.GetBugValidationDistribution(context.TODO(), nameDomain.Domain, period, status)
	if err != nil || distributions == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(distributions, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 3 - Host/Domain Bugs Exposure
func (l *BugDiscoveryTimelineHandler) HostBugsExposureController(c *fiber.Ctx) error {
	var response payload.Response

	period := c.QueryInt("period")
	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	exposure, err := l.service.GetHostBugsExposure(context.TODO(), nameDomain.Domain, period)
	if err != nil || exposure == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(exposure, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 3 - Pentesters Activity Statistics
func (l *BugDiscoveryTimelineHandler) PentestersActivityStatsController(c *fiber.Ctx) error {
	var response payload.Response

	period := c.QueryInt("period")
	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	activity, err := l.service.GetPentestersActivityStats(context.TODO(), nameDomain.Domain, period)
	if err != nil || activity == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(activity, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

// NEW: Chart 4 - Bug Type Frequency
func (l *BugDiscoveryTimelineHandler) BugTypeFrequencyController(c *fiber.Ctx) error {
	var response payload.Response

	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	period := c.QueryInt("period")
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	frequency, err := l.service.GetBugTypeFrequency(context.TODO(), nameDomain.Domain, period)
	if err != nil || frequency == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(frequency, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

func (l *BugDiscoveryTimelineHandler) GetTotalFindingsWithTrendController(c *fiber.Ctx) error {
	var response payload.Response

	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	frequency, err := l.service.GetTotalFindingsWithTrend(context.TODO(), nameDomain.Domain)
	if err != nil || frequency == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(frequency, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

func (l *BugDiscoveryTimelineHandler) PentesterEffectivenessController(c *fiber.Ctx) error {
	var response payload.Response

	// JWT Token validation
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	frequency, err := l.service.GetRealTimePentesterStatus(context.TODO(), nameDomain.Domain)
	if err != nil || frequency == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(frequency, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}
func (l *BugDiscoveryTimelineHandler) GetLogActivityController(c *fiber.Ctx) error {
	var response payload.Response

	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	params := domain_overview.LogActivityPaginationParams{
		Domain:    nameDomain.Domain,
		EndDate:   c.Query("end_date"),
		StartDate: c.Query("start_date"),
		Search:    c.Query("search"),
	}

	// Load semua data (default 1 bulan, desc by time)
	frequency, err := l.service.GetLogActivity(context.TODO(), params)
	if err != nil || frequency == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	// Ambil params cursor dan size
	cursor, _ := strconv.Atoi(c.Query("cursor"))
	size, _ := strconv.Atoi(c.Query("size", "1"))
	direction := c.Query("direction") // next / previous

	// Paginate
	pageData, pagination := paginateSimple(frequency.Data, cursor, size, direction)

	result := &domain_overview.LogActivityResponse{
		Data:       pageData,
		Pagination: pagination,
	}
	if (len(result.Data) == 0 && !result.Pagination.HasPrevious) ||
		(len(result.Data) == 0 && !result.Pagination.HasNext) {

		result.Data = nil
		result.Pagination.Size = 0
		response = payload.NewErrorResponse(errorenum.DataNotFound)

		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(result, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)

}

// Helper functions (existing)
func addAlpha(hex string, alpha int) string {
	if alpha < 0 {
		alpha = 0
	}
	if alpha > 255 {
		alpha = 255
	}
	return fmt.Sprintf("%s%02X", hex, alpha)
}
func paginateSimple(results []domain_overview.LogActivity, cursor, size int, direction string) ([]domain_overview.LogActivity, domain_overview.PaginationInfo) {

	total := len(results)
	if total == 0 {
		return []domain_overview.LogActivity{}, domain_overview.PaginationInfo{
			Size:        0,
			HasNext:     false,
			HasPrevious: false,
		}
	}

	// Hitung startIndex berdasarkan cursor + direction
	startIndex := cursor
	if direction == "next" {
		startIndex = cursor + size
	} else if direction == "previous" {
		startIndex = cursor - size
		if startIndex < 0 {
			startIndex = 0
		}
	}

	// Hitung end index
	endIndex := startIndex + size
	if endIndex > total {
		endIndex = total
	}

	// Slice data
	page := results[startIndex:endIndex]

	// Assign nomor
	for i := range page {
		page[i].No = strconv.Itoa(startIndex + i + 1)
	}

	// Pagination info
	pagination := domain_overview.PaginationInfo{
		Size:        len(page),
		HasNext:     endIndex < total,
		HasPrevious: startIndex > 0,
	}

	return page, pagination
}

func ConvertToChartData(stats []domain_overview.VulnStat) []domain_overview.ChartData {
	var charts []domain_overview.ChartData

	for _, stat := range stats {
		color := randomColor()
		charts = append(charts, domain_overview.ChartData{
			Name:  stat.Name,
			Type:  "line",
			Stack: "Total",
			Label: domain_overview.Label{Show: true, Position: "top"},
			AreaStyle: domain_overview.AreaStyle{
				Color: addAlpha(color, 153), // 153 = 0x99 = transparansi ~60%
			},
			LineStyle: domain_overview.LineStyle{
				Color: color,
				Width: 2,
			},
			Emphasis: domain_overview.Emphasis{Focus: "series"},
			Data:     stat.Data,
		})
	}
	return charts
}

func randomColor() string {
	rand.Seed(time.Now().UnixNano())

	for {
		r := rand.Intn(256)
		g := rand.Intn(256)
		b := rand.Intn(256)
		brightness := 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
		if brightness > 40 && brightness < 220 {
			return fmt.Sprintf("#%02X%02X%02X", r, g, b)
		}
	}
}
