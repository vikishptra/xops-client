package domain_user

import (
	"mime/multipart"

	"github.com/elastic/go-elasticsearch/v8"

	"xops-admin/model"
)

type ClientUseCase interface {
	CreateUserClient(req *CreateClientRequest) (*ClientResponse, error)
	UpdateUserClient(id string, req *UpdateClientRequest) error
	GetClientWithLastPentest(clientID, domain string, es *elasticsearch.Client) (*ClientPenTestInfo, error)
	GetDomainByClientID(id string) (*model.DomainClient, error)
}

type ClientPenTestInfo struct {
	LogoCompany string `json:"logo_company"`
	CompanyName string `json:"company_name"`
	LastTest    string `json:"last_test"`
}

type CreateClientRequest struct {
	CompanyName string                `json:"company_name" binding:"required"`
	Email       string                `json:"email" binding:"required,email"`
	Domains     []string              `json:"domains" binding:"required"`
	StartDate   string                `json:"start_date" binding:"required"`
	EndDate     string                `json:"end_date" binding:"required"`
	Logo        *multipart.FileHeader `json:"logo"`
	IsVerified  bool                  `json:"is_verified"`
	IsTwoFA     bool                  `json:"is_two_fa"`
}

type UpdateClientRequest struct {
	CompanyName string                `json:"company_name"`
	Email       string                `json:"email"`
	Domains     []string              `json:"domains"`
	StartDate   string                `json:"start_date"`
	EndDate     string                `json:"end_date"`
	Logo        *multipart.FileHeader `json:"logo"`
}

type ClientResponse struct {
	User     *model.User   `json:"user"`
	Client   *model.Client `json:"client"`
	Password string        `json:"password"`
}
