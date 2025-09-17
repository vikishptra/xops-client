package domain

import (
	"context"
	domain_user "xops-admin/domain/user/client"
	"xops-admin/model"

	"github.com/elastic/go-elasticsearch/v8"
)

type ClientRepository interface {
	CreateClient(client *model.Client) error
	UpdateClient(client *model.Client) error
	GetClientByID(id string) (*model.Client, error)
	GetClientByUserID(userID string) (*model.Client, error)
	GetActiveDomainsByClientID(clientID string) ([]model.DomainClient, error)
	DomainExistsForClient(clientID, domain string) (bool, error)
	GetDomainByClientID(id string) (*model.DomainClient, error)
	GetClientWithLastPentest(ctx context.Context, id string, domain string, es *elasticsearch.Client) (*domain_user.ClientPenTestInfo, error)
}
