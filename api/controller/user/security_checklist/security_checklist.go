package controller_security_checklist

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_overview "xops-admin/domain/user/overview"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	util_jwttoken "xops-admin/util/token_jwt"
)

type SecurityCheklistHandler struct {
	service domain_overview.SecurityCheklistUseCase
}

func NewSecurityCheklistHandler(service domain_overview.SecurityCheklistUseCase) *SecurityCheklistHandler {
	return &SecurityCheklistHandler{
		service: service,
	}
}

func (l *SecurityCheklistHandler) GetTotalFindingsController(c *fiber.Ctx) error {
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
	chartData, err := l.service.GetTotalFindings(context.TODO(), nameDomain.Domain)
	if err != nil || chartData == nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	response = payload.NewSuccessResponse(chartData, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}
func (l *SecurityCheklistHandler) GetTotalBugStatusListController(c *fiber.Ctx) error {
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
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	result, err := l.service.GetTotalBugStatusList(context.TODO(), nameDomain.Domain)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(result, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}
func (l *SecurityCheklistHandler) GetSecurityChecklistTableController(c *fiber.Ctx) error {
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
	params := domain_overview.PaginationParams{
		Size:      10,       // default size
		SortOrder: "newest", // default sort order
	}

	// Parse size parameter
	if sizeStr := c.Query("size"); sizeStr != "" {
		if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 {
			params.Size = size
		}
	}
	params.LastPageID = c.Query("last_page_id")
	params.LastPageTime = c.Query("last_page_time")
	params.Direction = c.Query("direction")
	params.Status = c.Query("status")
	urlParam := c.Query("urls")
	if urlParam != "" {
		params.Urls = strings.Split(urlParam, ",")
		// Trim whitespace dari setiap URL
		for i, url := range params.Urls {
			params.Urls[i] = strings.TrimSpace(url)
		}
	}
	params.Period = c.QueryInt("period")
	params.Validation = c.Query("validation")
	params.Severity = c.Query("severity")
	params.Search = c.Query("search")
	if params.Validation == "all_validation" {
		params.Validation = ""
	}
	if params.Severity == "all_severity" {
		params.Severity = ""
	}
	if params.Status == "all_status" {
		params.Status = ""
	}
	fmt.Println(params)
	// Parse sort_order parameter
	if sortOrder := c.Query("sort_order"); sortOrder != "" {
		if sortOrder == "oldest" || sortOrder == "newest" {
			params.SortOrder = sortOrder
		}
	}
	result, err := l.service.GetSecurityChecklistTable(context.TODO(), nameDomain.Domain, params)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	if (len(result.Data) == 0 && !result.Pagination.HasPrevious) || (len(result.Data) == 0 && !result.Pagination.HasNext) {
		result.Data = nil
		result.Message = errorenum.DataNotFound
		result.Pagination.Size = 0
		return c.Status(fiber.StatusNotFound).JSON(result)
	}
	result.Message = "OK"
	return c.Status(fiber.StatusOK).JSON(result)
}
func (l *SecurityCheklistHandler) GetSecurityChecklistTableDetailIdController(c *fiber.Ctx) error {
	var response payload.Response

	idData := c.Params("id")
	result, err := l.service.GetSecurityChecklistDetailByESID(context.TODO(), idData)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	response = payload.NewSuccessResponse(result, errorenum.OKSuccess)
	return c.Status(fiber.StatusOK).JSON(response)
}

func (l *SecurityCheklistHandler) GetURLListController(c *fiber.Ctx) error {
	var response payload.Response

	// 🔑 Ambil & validasi token
	loadconfig, _ := config.LoadConfig(".")
	refresh_token := c.Cookies("refresh_token")
	id, err := util_jwttoken.ValidateToken(refresh_token, loadconfig.RefreshTokenPublicKey)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// 🔑 Ambil domain berdasarkan client ID
	nameDomain, err := l.service.GetDomainByClientID(id.UserID)
	if err != nil {
		response = payload.NewErrorResponse(err)
		return c.Status(fiber.StatusUnauthorized).JSON(response)
	}

	// 🔎 Parse query parameters
	params := domain_overview.URLListParams{
		Limit: 5, // default limit
	}

	// Parse page
	if pageStr := c.Query("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}
	// Parse limit
	if limitStr := c.Query("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			params.Limit = limit
		}
	}

	// Parse search
	params.Search = c.Query("search")

	// Parse direction (next/previous)
	if direction := c.Query("direction"); direction != "" {
		if direction == "next" {
			params.Page++
		} else if direction == "previous" && params.Page > 1 {
			params.Page--
		}
	}

	// 🚀 Call service untuk ambil data
	result, err := l.service.GetURLList(context.TODO(), nameDomain.Domain, params)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}
	// ❌ Kalau kosong, return not found
	if len(result.Data) == 0 {

		response := domain_overview.URLListResponse{
			Success: false,
			Message: errorenum.DataNotFound,
			Data:    nil,
			Pagination: domain_overview.PaginationInfo{
				Size:        0,
				HasNext:     false,
				HasPrevious: false,
			},
		}
		return c.Status(fiber.StatusNotFound).JSON(response)
	}
	// ✅ Success response
	result.Message = errorenum.OKSuccess
	result.Success = true
	return c.Status(fiber.StatusOK).JSON(result)
}

func (l *SecurityCheklistHandler) ListVulnController(c *fiber.Ctx) error {
	search := c.Query("search")
	page, _ := strconv.Atoi(c.Query("page"))
	limit, _ := strconv.Atoi(c.Query("limit", "5"))

	// // direction=next/previous
	// direction := c.Query("direction")
	// if direction == "next" {
	// 	page++
	// } else if direction == "previous" && page > 1 {
	// 	page--
	// }

	listVuln, total, err := l.service.ListVulnerabilityNames(context.TODO(), search, page, limit)
	if err != nil || len(listVuln) == 0 {
		response := domain_overview.VulnerabilityItemResponse{
			Success: false,
			Message: errorenum.DataNotFound,
			Data:    nil,
			Pagination: domain_overview.PaginationInfo{
				Size:        0,
				HasNext:     false,
				HasPrevious: false,
			},
		}
		return c.Status(fiber.StatusNotFound).JSON(response)
	}

	// Hitung hasNext & hasPrevious
	hasNext := page*limit < int(total)
	hasPrevious := page > 1

	response := domain_overview.VulnerabilityItemResponse{
		Success: true,
		Message: "OK",
		Data:    listVuln,
		Pagination: domain_overview.PaginationInfo{
			Size:        limit,
			HasNext:     hasNext,
			HasPrevious: hasPrevious,
		},
	}

	return c.Status(fiber.StatusOK).JSON(response)
}

func (h *SecurityCheklistHandler) BulkUpdate(c *fiber.Ctx) error {
	var req domain_overview.BulkUpdateSecurityChecklistRequest
	var response payload.Response

	// Parse body JSON
	if err := c.BodyParser(&req); err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Call usecase
	_, err := h.service.BulkUpdateSecurityChecklist(c.Context(), req)
	if err != nil {
		response = payload.NewErrorResponse(errorenum.DataNotFound)
		return c.Status(fiber.StatusNotFound).JSON(response)
	}
	response = payload.NewSuccessResponse(req.Updates, errorenum.OKSuccess)
	// Return response dari usecase
	return c.Status(fiber.StatusOK).JSON(response)
}
