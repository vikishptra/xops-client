package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"gorm.io/gorm"

	"xops-admin/domain"
	domain_user "xops-admin/domain/user/client"
	"xops-admin/model"
)

type ClientRepo struct {
	db *gorm.DB
}

func NewClientRepo(db *gorm.DB) domain.ClientRepository {
	return &ClientRepo{
		db: db,
	}
}
func (r *ClientRepo) GetClientWithLastPentest(ctx context.Context, id string, domain string, es *elasticsearch.Client) (*domain_user.ClientPenTestInfo, error) {
	// 1. Ambil data client dulud
	var client model.Client
	if err := r.db.
		Where("id_user = ?", id).
		First(&client).Error; err != nil {
		return nil, err
	}

	// 2. Query ke Elastic untuk cari last pentest date
	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": domain, // asumsinya ada field domain di client
			},
		},
		"aggs": map[string]interface{}{
			"last_test": map[string]interface{}{
				"max": map[string]interface{}{
					"field": "time",
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := es.Search(
		es.Search.WithContext(ctx),
		es.Search.WithIndex("proxy-traffic-new"),
		es.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elastic error: %s", res.String())
	}

	var esResp map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&esResp); err != nil {
		return nil, err
	}

	var lastDate string
	if agg, ok := esResp["aggregations"].(map[string]interface{}); ok {
		if lastTestAgg, ok := agg["last_test"].(map[string]interface{}); ok {
			if lastTestAgg["value"] != nil {
				val := int64(lastTestAgg["value"].(float64))
				tm := time.UnixMilli(val)
				// Format ke string sesuai kebutuhan
				lastDate = tm.Format("Mon, 02 Jan 2006 15:04")
			}
		}
	}
	host := "https://xops-api.sector.co.id/static/" + client.LogoCompany
	// 3. Return gabungan data client + last pentest
	return &domain_user.ClientPenTestInfo{
		CompanyName: client.CompanyName,
		LogoCompany: host,
		LastTest:    lastDate,
	}, nil
}

func (r *ClientRepo) GetClientByUserID(userID string) (*model.Client, error) {
	var client model.Client
	err := r.db.Preload("DomainClient").Where("id_user = ?", userID).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepo) CreateClient(client *model.Client) error {
	return r.db.Create(client).Error
}

func (r *ClientRepo) UpdateClient(client *model.Client) error {
	return r.db.Session(&gorm.Session{FullSaveAssociations: true}).Updates(client).Error
}

func (r *ClientRepo) GetClientByID(id string) (*model.Client, error) {
	var client model.Client
	err := r.db.Preload("DomainClient").Where("id = ?", id).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}
func (r *ClientRepo) GetDomainByClientID(id string) (*model.DomainClient, error) {
	var client model.Client
	// cari client dulu
	if err := r.db.
		Where("id_user = ?", id).
		First(&client).Error; err != nil {
		return nil, err
	}

	var domain model.DomainClient
	// lalu cari domain dari client_id
	if err := r.db.
		Where("id_client = ?", client.Id).
		Order("created_at DESC").
		First(&domain).Error; err != nil {
		return nil, err
	}
	return &domain, nil
}

// Additional helper method to get active domains for a client
func (r *ClientRepo) GetActiveDomainsByClientID(clientID string) ([]model.DomainClient, error) {
	var domains []model.DomainClient
	err := r.db.Where("id_client = ? AND active = ?", clientID, true).Find(&domains).Error
	return domains, err
}

// Method to check if a domain exists for a client
func (r *ClientRepo) DomainExistsForClient(clientID, domain string) (bool, error) {
	var count int64
	err := r.db.Model(&model.DomainClient{}).
		Where("id_client = ? AND domain = ?", clientID, domain).
		Count(&count).Error
	return count > 0, err
}
