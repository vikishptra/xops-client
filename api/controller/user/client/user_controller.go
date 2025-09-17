package controller_client

import (
	"strings"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gofiber/fiber/v2"

	"xops-admin/config"
	domain_client "xops-admin/domain/user/client"
	domain_user "xops-admin/domain/user/client"
	"xops-admin/helper/errorenum"
	"xops-admin/helper/payload"
	util_jwttoken "xops-admin/util/token_jwt"
)

type ClientUserHandler struct {
	usecase       domain_user.ClientUseCase
	elasticSearch *elasticsearch.Client
}

func NewClientUserHandler(u domain_user.ClientUseCase, es *elasticsearch.Client) *ClientUserHandler {
	return &ClientUserHandler{
		usecase:       u,
		elasticSearch: es,
	}
}

func (h *ClientUserHandler) CreateClient(c *fiber.Ctx) error {
	var response payload.Response
	var req domain_client.CreateClientRequest

	// Parse form data
	req.CompanyName = c.FormValue("company_name")
	req.Email = c.FormValue("email")
	req.StartDate = c.FormValue("start_date")
	req.EndDate = c.FormValue("end_date")

	req.IsVerified = true
	req.IsTwoFA = true

	// Parse domains (comma-separated)
	domainsStr := c.FormValue("domains")
	if domainsStr != "" {
		req.Domains = strings.Split(domainsStr, ",")
		// Trim spaces
		for i, domain := range req.Domains {
			req.Domains[i] = strings.TrimSpace(domain)
		}
	}

	// Handle file upload
	file, err := c.FormFile("logo")
	if err == nil {
		req.Logo = file
	}

	// Validate required fields
	if req.CompanyName == "" || req.Email == "" || len(req.Domains) == 0 {
		response = payload.NewErrorResponse("Missing required fields")
		return c.Status(fiber.StatusBadRequest).JSON(response)
	}

	// Create client (this will create user first, then client)
	clientResponse, err := h.usecase.CreateUserClient(&req)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response = payload.NewSuccessResponse(clientResponse.Client, errorenum.OKSuccess)
	return c.Status(fiber.StatusCreated).JSON(response)
}
func (h *ClientUserHandler) GetDomainClient(c *fiber.Ctx) error {
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

	// Create client (this will create user first, then client)
	clientResponse, err := h.usecase.GetClientWithLastPentest(id.UserID, nameDomain.Domain, h.elasticSearch)
	if err != nil {
		response = payload.NewErrorResponse(err.Error())
		return c.Status(fiber.StatusInternalServerError).JSON(response)
	}

	response = payload.NewSuccessResponse(clientResponse, errorenum.OKSuccess)
	return c.Status(fiber.StatusCreated).JSON(response)
}
