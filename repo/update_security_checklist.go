// Repository Implementation
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"gorm.io/gorm"

	"xops-admin/domain"
	domain_overview "xops-admin/domain/user/overview"
	"xops-admin/helper/errorenum"
	"xops-admin/model"
)

type BulkUpdateSecurityChecklistRepo struct {
	db *gorm.DB
	es *elasticsearch.Client
}

func NewBulkUpdateSecurityChecklistRepository(db *gorm.DB, es *elasticsearch.Client) domain.BulkUpdateSecurityChecklistRepository {
	return &BulkUpdateSecurityChecklistRepo{
		db: db,
		es: es,
	}
}

// UpdateSecurityChecklistItems updates multiple items in Elasticsearch and inserts to PostgreSQL if needed
func (r *BulkUpdateSecurityChecklistRepo) UpdateSecurityChecklistItems(ctx context.Context, updates []domain_overview.SecurityChecklistBulkUpdate) error {
	// Start transaction for PostgreSQL operations
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Process each update
	for _, update := range updates {
		// Update Elasticsearch document
		if err := r.updateElasticsearchDocument(ctx, update); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to update elasticsearch document %s: %w", update.ID, err)
		}

		// Check if we need to insert to PostgreSQL
		shouldInsertToDB := r.shouldInsertToPostgreSQL(update)
		if shouldInsertToDB {
			if err := r.insertToPostgreSQL(ctx, tx, update); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to insert to postgresql for document %s: %w", update.ID, err)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// updateElasticsearchDocument updates a single document in Elasticsearch
func (r *BulkUpdateSecurityChecklistRepo) updateElasticsearchDocument(ctx context.Context, update domain_overview.SecurityChecklistBulkUpdate) error {
	// Prepare update body
	updateBody := map[string]interface{}{
		"doc": map[string]interface{}{},
	}

	// Add fields to update
	if update.Severity != "" {
		updateBody["doc"].(map[string]interface{})["severity"] = strings.ToUpper(update.Severity)
	}
	if update.Status != "" {
		updateBody["doc"].(map[string]interface{})["status"] = strings.ToUpper(update.Status)
	}
	if update.Validation != "" {
		updateBody["doc"].(map[string]interface{})["validation"] = strings.ToUpper(update.Validation)
	}
	if update.Vulnerability != "" {
		updateBody["doc"].(map[string]interface{})["vulnerability"] = update.Vulnerability
	}

	// Add updated timestamp

	// Convert to JSON
	bodyBytes, err := json.Marshal(updateBody)
	if err != nil {
		return fmt.Errorf("failed to marshal update body: %w", err)
	}

	// Execute update
	res, err := r.es.Update(
		"proxy-traffic-new", // index name
		update.ID,           // document ID
		strings.NewReader(string(bodyBytes)),
		r.es.Update.WithContext(ctx),
		r.es.Update.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("failed to execute elasticsearch update: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch update failed with status: %s", res.Status())
	}

	return nil
}

// shouldInsertToPostgreSQL checks if the update requires insertion to PostgreSQL
func (r *BulkUpdateSecurityChecklistRepo) shouldInsertToPostgreSQL(update domain_overview.SecurityChecklistBulkUpdate) bool {
	// Insert to PostgreSQL if validation is FIXED/PENDING or status is SUCCESS/FAILED
	validation := strings.ToUpper(update.Validation)
	status := strings.ToUpper(update.Status)

	return (validation == "FIXED" || validation == "PENDING") ||
		(status == "SUCCESS" || status == "FAILED")
}

func (r *BulkUpdateSecurityChecklistRepo) insertToPostgreSQL(ctx context.Context, tx *gorm.DB, update domain_overview.SecurityChecklistBulkUpdate) error {
	// Ambil vulnerability ID
	vulnerabilityID, err := r.getVulnerabilityIDByName(ctx, tx, update.Vulnerability)
	if err != nil {
		return fmt.Errorf("failed to get vulnerability ID: %w", err)
	}
	if vulnerabilityID == 0 {
		return errorenum.SomethingError
	}

	// Ambil request & response dari Elasticsearch berdasarkan ID
	doc, err := r.getDocumentFromElasticsearch(ctx, update.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch request/response from elasticsearch: %w", err)
	}

	requestStr, _ := doc["request"].(string)
	responseStr, _ := doc["response"].(string)
	flagDomain, _ := doc["flag_domain"].(string)

	// Cek apakah record sudah ada berdasarkan IdElastic
	var existingBug model.ListBug
	err = tx.Where("id_elastic = ?", update.ID).First(&existingBug).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("failed to check existing record: %w", err)
	}

	// Buat data untuk insert/update
	bugData := model.ListBug{
		IdListVulnerability: vulnerabilityID,
		IdElastic:           update.ID,
		Host:                update.Host,
		Method:              update.Method,
		StatusCode:          update.StatusCode,
		Tool:                update.Tool,
		URL:                 update.URL,
		PentesterIP:         update.PentesterIP,
		Severity:            strings.ToUpper(update.Severity),
		Status:              strings.ToUpper(update.Status),
		Validation:          strings.ToUpper(update.Validation),
		Vulnerability:       update.Vulnerability,
		FlagDomain:          flagDomain,
		Request:             requestStr,
		Response:            responseStr,
		UpdatedAt:           time.Now(),
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Record tidak ada, lakukan insert
		bugData.CreatedAt = time.Now()
		if err := tx.Create(&bugData).Error; err != nil {
			return fmt.Errorf("failed to insert list bug: %w", err)
		}
	} else {
		// Record sudah ada, lakukan update
		// Preserve CreatedAt dari record yang sudah ada
		bugData.Id = existingBug.Id
		bugData.CreatedAt = existingBug.CreatedAt

		if err := tx.Save(&bugData).Error; err != nil {
			return fmt.Errorf("failed to update list bug: %w", err)
		}
	}

	return nil
}

// getVulnerabilityIDByName gets vulnerability ID by name, creates new one if not exists
func (r *BulkUpdateSecurityChecklistRepo) getVulnerabilityIDByName(ctx context.Context, tx *gorm.DB, vulnerabilityName string) (int64, error) {
	var vulnerability model.ListVulnerability

	// Try to find existing vulnerability
	err := tx.Where("name_bug = ?", vulnerabilityName).First(&vulnerability).Error
	if err == nil {
		// Found existing vulnerability
		return vulnerability.UniqueID, nil
	}

	if err != gorm.ErrRecordNotFound {
		return 0, fmt.Errorf("failed to query vulnerability: %w", err)
	}

	return 0, errorenum.SomethingError
}
func (r *BulkUpdateSecurityChecklistRepo) getDocumentFromElasticsearch(ctx context.Context, id string) (map[string]interface{}, error) {
	res, err := r.es.Get(
		"proxy-traffic-new", // index name
		id,
		r.es.Get.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get document from elasticsearch: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch get failed: %s", res.Status())
	}

	var doc map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode elasticsearch document: %w", err)
	}

	source, ok := doc["_source"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing _source in elasticsearch document")
	}

	return source, nil
}
