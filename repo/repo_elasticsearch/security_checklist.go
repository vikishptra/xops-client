package repo_elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"

	"xops-admin/domain"
	domain_overview "xops-admin/domain/user/overview"
	util_uuid "xops-admin/util/uuid"
)

type SecurityCheklistRepo struct {
	client *elasticsearch.Client
}

// GetTotalFindings implements domain_overview.SecurityChecklistRepository.
func (s *SecurityCheklistRepo) GetTotalFindings(ctx context.Context, domain_overviewName string) (*[]domain_overview.SeverityCountTotalFindings, error) {
	query := s.buildTotalFindingsQuery(domain_overviewName)
	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute total findings query: %w", err)
	}
	return s.parseTotalFindings(response)
}

// GetTotalBugStatusList with pagination and sorting
func (s *SecurityCheklistRepo) GetTotalBugStatusList(ctx context.Context, domain_overviewName string) (*domain_overview.ResponseTotalBugStatusItem, error) {
	query := s.buildTotalBugStatusQuery(domain_overviewName)
	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute total bug status query: %w", err)
	}
	return s.parseTotalBugStatusList(response)
}

// GetSecurityChecklistTable with pagination and sorting
func (s *SecurityCheklistRepo) GetSecurityChecklistTable(ctx context.Context, domain_overviewName string, params domain_overview.PaginationParams) (*domain_overview.SecurityChecklistTableResponse, error) {
	query := s.buildSecurityChecklistTableQuery(domain_overviewName, params)
	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute security checklist table query: %w", err)
	}
	return s.parseSecurityChecklistTable(response, params)
}

func (s *SecurityCheklistRepo) buildTotalFindingsQuery(flagDomain string) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "severity.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"validation.keyword": []string{"FIXED", "VALIDATED", "PENDING"},
			},
		},
	}

	// Add domain_overview filter if provided
	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	// Exclude invalid severity values
	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"severity.keyword": "-"}},
		{"term": map[string]interface{}{"severity.keyword": ""}},
	}

	return map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must":     mustClauses,
				"must_not": mustNotClauses,
			},
		},
		"aggs": map[string]interface{}{
			"severity_breakdown": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity.keyword",
					"size":  1000,
				},
			},
		},
	}
}

func (s *SecurityCheklistRepo) buildSecurityChecklistTableQuery(flagDomain string, params domain_overview.PaginationParams) map[string]interface{} {
	mustClauses := []map[string]interface{}{}

	if params.Search != "" {
		searchQuery := map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					// Exact matches (fastest) - higher boost score
					{
						"multi_match": map[string]interface{}{
							"query":  params.Search,
							"fields": []string{"host.keyword^2", "status_code.keyword^2", "url.keyword^1.5"},
							"type":   "phrase",
							"boost":  2.0,
						},
					},
					// Prefix matches (faster than full wildcard)
					{
						"multi_match": map[string]interface{}{
							"query":  params.Search,
							"fields": []string{"host", "url"},
							"type":   "phrase_prefix",
							"boost":  1.5,
						},
					},
					// Wildcard as fallback (slowest but most flexible)
					{
						"bool": map[string]interface{}{
							"should": []map[string]interface{}{
								{
									"wildcard": map[string]interface{}{
										"host.keyword": fmt.Sprintf("*%s*", strings.ToLower(params.Search)),
									},
								},
								{
									"wildcard": map[string]interface{}{
										"status_code.keyword": fmt.Sprintf("*%s*", params.Search),
									},
								},
								{
									"wildcard": map[string]interface{}{
										"url.keyword": fmt.Sprintf("*%s*", params.Search),
									},
								},
							},
							"minimum_should_match": 1,
							"boost":                1.0,
						},
					},
				},
				"minimum_should_match": 1,
			},
		}
		mustClauses = append(mustClauses, searchQuery)
	}

	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	// Filter by status
	if params.Status != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"status.keyword": strings.ToUpper(params.Status),
			},
		})
	}

	if len(params.Urls) > 0 {
		// Remove duplicates and empty strings
		urlsToFilter := removeDuplicateStrings(params.Urls)

		if len(urlsToFilter) == 1 {
			// Single URL - use term query for better performance
			mustClauses = append(mustClauses, map[string]interface{}{
				"term": map[string]interface{}{
					"url.keyword": urlsToFilter[0],
				},
			})
		} else {
			// Multiple URLs - use terms query
			mustClauses = append(mustClauses, map[string]interface{}{
				"terms": map[string]interface{}{
					"url.keyword": urlsToFilter,
				},
			})
		}
	}

	// Filter by validation
	if params.Validation != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"validation.keyword": strings.ToUpper(params.Validation),
			},
		})
	}

	if params.Severity != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"severity.keyword": strings.ToUpper(params.Severity),
			},
		})
	}

	// Filter by period (time range) - FIXED DATE FORMAT
	if params.Period > 0 {
		// Use ISO format that Elasticsearch expects
		now := time.Now()
		fromTime := now.AddDate(0, 0, -params.Period).Format("2006-01-02T15:04:05Z")
		toTime := now.Format("2006-01-02T15:04:05Z")

		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte":    fromTime,
					"lte":    toTime,
					"format": "strict_date_optional_time", // Specify format explicitly
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	// Set default size
	if params.Size <= 0 {
		params.Size = 10
	}

	// Determine sort order based on direction and user preference
	sortOrder := "desc"
	if params.SortOrder == "oldest" {
		sortOrder = "asc"
	}

	// Determine tie-breaker order
	tieBreaker := "asc"

	// IMPORTANT: For previous page navigation, we need to reverse the sort order temporarily
	// to get the correct records, then reverse them back in the parsing function
	if params.Direction == "previous" {
		if sortOrder == "desc" {
			sortOrder = "asc"
		} else {
			sortOrder = "desc"
		}
		// Also reverse tie-breaker for previous direction
		tieBreaker = "desc"
	}

	query := map[string]interface{}{
		"size": params.Size + 1, // Always get one extra to check for more data
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"sort": []map[string]interface{}{
			{"time": map[string]interface{}{"order": sortOrder}},
			{"id.keyword": map[string]interface{}{"order": tieBreaker}}, // tie-breaker
		},
	}

	// Use search_after for pagination
	if params.LastPageTime != "" && params.LastPageID != "" && params.Direction != "debug" {
		// Use raw string format since that's how data is stored in ES
		query["search_after"] = []interface{}{params.LastPageTime, params.LastPageID}
		log.Printf("NEW: Using raw string search_after: [time=%s, id=%s] with sort=[time:%s, id:%s]",
			params.LastPageTime, params.LastPageID, sortOrder, tieBreaker)
	}

	return query
}

func (s *SecurityCheklistRepo) parseSecurityChecklistTable(response *domain.SearchResponse, params domain_overview.PaginationParams) (*domain_overview.SecurityChecklistTableResponse, error) {
	results := make([]domain_overview.SecurityChecklistItem, 0)

	// DEBUG: Log ES response details
	// log.Printf("=== PARSING DEBUG ===")
	// log.Printf("Total hits: %d", len(response.Hits.Hits))
	// log.Printf("Params - Direction: %s, LastPageID: %s, LastPageTime: %s, Size: %d",
	// 	params.Direction, params.LastPageID, params.LastPageTime, params.Size)

	if len(response.Hits.Hits) > 0 {
		log.Printf("First hit: ID=%s, Time=%v (type: %T)",
			response.Hits.Hits[0].Source.ID,
			response.Hits.Hits[0].Source.Time,
			response.Hits.Hits[0].Source.Time)
		if len(response.Hits.Hits) > 1 {
			log.Printf("Last hit: ID=%s, Time=%v (type: %T)",
				response.Hits.Hits[len(response.Hits.Hits)-1].Source.ID,
				response.Hits.Hits[len(response.Hits.Hits)-1].Source.Time,
				response.Hits.Hits[len(response.Hits.Hits)-1].Source.Time)
		}

		// Special check: jika direction=previous dan first hit ID sama dengan LastPageID
		if params.Direction == "previous" && response.Hits.Hits[0].Source.ID == params.LastPageID {
			log.Printf("WARNING: First hit matches LastPageID - this should not happen for previous direction!")
		}

		// Log all hit IDs for debugging
		allIDs := make([]string, len(response.Hits.Hits))
		for i, hit := range response.Hits.Hits {
			allIDs[i] = hit.Source.ID
		}
		// log.Printf("All hit IDs: %v", allIDs)
	}

	// Check if there are more records available
	totalHits := len(response.Hits.Hits)
	hasMoreData := totalHits > params.Size

	// Get actual data (exclude the extra record used for pagination check)
	actualDataSize := totalHits
	if hasMoreData {
		actualDataSize = params.Size
	}

	// log.Printf("DataSize: %d, HasMoreData: %v, ActualDataSize: %d", totalHits, hasMoreData, actualDataSize)

	// Get the records to process
	hits := response.Hits.Hits[:actualDataSize]

	// IMPORTANT: If direction = "previous", reverse the results since we reversed the sort order in query
	if params.Direction == "previous" {
		for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
			hits[i], hits[j] = hits[j], hits[i]
		}
	}

	// Special case: Jika direction = "previous" dan tidak ada data,
	// kembalikan respons kosong dengan pagination yang benar
	if params.Direction == "previous" && actualDataSize == 0 {
		log.Printf("Previous direction with no data - returning empty result")
		return &domain_overview.SecurityChecklistTableResponse{
			Data: []domain_overview.SecurityChecklistItem{},
			Pagination: domain_overview.PaginationInfo{
				Size:        params.Size,
				HasNext:     true,  // Bisa next ke halaman selanjutnya
				HasPrevious: false, // Sudah di awal, tidak ada previous
			},
		}, nil
	}

	// Additional check: Jika direction = "previous" dan data yang dikembalikan
	// mengandung LastPageID yang sama, ini error
	if params.Direction == "previous" && params.LastPageID != "" {
		for _, hit := range hits {
			if hit.Source.ID == params.LastPageID {
				log.Printf("ERROR: Previous direction returned the same ID as LastPageID: %s", params.LastPageID)
				// Return empty result karena ini menunjukkan kita sudah di halaman pertama
				return &domain_overview.SecurityChecklistTableResponse{
					Data: []domain_overview.SecurityChecklistItem{},
					Pagination: domain_overview.PaginationInfo{
						Size:        params.Size,
						HasNext:     true,  // Masih bisa next
						HasPrevious: false, // Sudah di awal
					},
				}, nil
			}
		}
	}

	// Process each hit
	for i, hit := range hits {
		doc := hit.Source

		// Parse time for display - use raw time since it's already in desired format
		displayTime := doc.Time

		displayTime = s.formatToIndonesianShort(fmt.Sprintf("%v", doc.Time))

		item := domain_overview.SecurityChecklistItem{
			ID:            doc.ID,
			Key:           fmt.Sprintf("%d", i+1),
			DateTime:      displayTime,
			HashID:        fmt.Sprintf("%d", i+1583),
			Host:          doc.Host,
			Method:        doc.Method,
			StatusCode:    doc.StatusCode,
			Tools:         doc.Tools,
			URL:           doc.URL,
			PentesterIP:   doc.IP,
			Severity:      util_uuid.Capitalize(doc.Severity),
			Status:        util_uuid.Capitalize(doc.Status),
			Validation:    util_uuid.Capitalize(doc.Validation),
			Vulnerability: doc.Vulnerability,
		}

		results = append(results, item)
	}

	// CORRECTED PAGINATION LOGIC
	paginationInfo := domain_overview.PaginationInfo{
		Size: params.Size,
	}

	// Fixed logic untuk pagination:
	isFirstPage := params.LastPageID == "" && params.LastPageTime == ""

	if params.Direction == "previous" {
		// Ketika direction = "previous", kita sedang navigasi mundur
		// Jika hasil kosong (actualDataSize == 0), berarti kita sudah di halaman pertama
		if actualDataSize == 0 {
			paginationInfo.HasPrevious = false // Tidak ada data sebelumnya
			paginationInfo.HasNext = true      // Masih bisa next ke halaman berikutnya
		} else {
			paginationInfo.HasPrevious = hasMoreData // Ada previous jika masih ada data lebih lama
			paginationInfo.HasNext = true            // Selalu ada next karena kita mundur dari halaman yang ada
		}
	} else {
		// Direction = "next" atau first page
		paginationInfo.HasPrevious = !isFirstPage // Ada previous jika bukan halaman pertama
		paginationInfo.HasNext = hasMoreData      // Ada next jika masih ada data lebih
	}

	log.Printf("Final pagination - HasNext: %v, HasPrevious: %v, IsFirstPage: %v, Direction: %s, ActualDataSize: %d",
		paginationInfo.HasNext, paginationInfo.HasPrevious, isFirstPage, params.Direction, actualDataSize)

	return &domain_overview.SecurityChecklistTableResponse{
		Data:       results,
		Pagination: paginationInfo,
	}, nil
}

// Helper function to safely format time
func (s *SecurityCheklistRepo) formatToIndonesianShort(timeStr string) string {
	// Try to parse various time formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05+07:00",
	}

	var parsedTime time.Time
	var err error

	for _, format := range formats {
		parsedTime, err = time.Parse(format, timeStr)
		if err == nil {
			break
		}
	}

	if err != nil {
		// log.Printf("Note: Time already in display format: %s", timeStr)
		return timeStr // Return as-is if already in display format
	}

	// Convert to Indonesian timezone (WIB = UTC+7)
	wib, _ := time.LoadLocation("Asia/Jakarta")
	localTime := parsedTime.In(wib)

	// Format to Indonesian short format
	return localTime.Format("02/01/06 15:04")
}

// parseTotalFindings parsing response dari Elasticsearch untuk breakdown severity
func (s *SecurityCheklistRepo) parseTotalFindings(response *domain.SearchResponse) (*[]domain_overview.SeverityCountTotalFindings, error) {
	// Daftar severity yang wajib ada
	expectedSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION"}

	// Simpan hasil ES dalam map biar gampang cek exist
	severityMap := make(map[string]int64)

	if severityAgg, ok := response.Aggregations["severity_breakdown"]; ok {
		if aggData, ok := severityAgg.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						if sev, ok := bucketData["key"].(string); ok {
							if docCount, ok := bucketData["doc_count"].(float64); ok {
								severityMap[sev] = int64(docCount)
							}
						}
					}
				}
			}
		}
	}

	// Susun hasil akhir sesuai urutan expectedSeverities
	results := make([]domain_overview.SeverityCountTotalFindings, 0, len(expectedSeverities))
	for i, sev := range expectedSeverities {
		count := severityMap[sev] // default 0 kalau tidak ada
		results = append(results, domain_overview.SeverityCountTotalFindings{
			ID:       fmt.Sprintf("%d", i+1),
			Severity: util_uuid.Capitalize(sev),
			Total:    count,
		})
	}

	return &results, nil
}

func (s *SecurityCheklistRepo) buildTotalBugStatusQuery(flagDomain string) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "vulnerability.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"validation.keyword": []string{"FIXED", "PENDING"},
			},
		},
	}

	// Add domain filter if provided
	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	return map[string]interface{}{
		"size": 0, // Tidak perlu hits data, hanya aggregation
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"aggs": map[string]interface{}{
			"vulnerability_breakdown": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "vulnerability.keyword",
					"size":  1000, // Ambil semua vulnerability types
				},
			},
		},
	}
}

func (s *SecurityCheklistRepo) parseTotalBugStatusList(response *domain.SearchResponse) (*domain_overview.ResponseTotalBugStatusItem, error) {
	results := make([]domain_overview.TotalBugStatusItem, 0)
	var total int64

	// Parse aggregations untuk vulnerability breakdown
	if vulnAgg, ok := response.Aggregations["vulnerability_breakdown"]; ok {
		if aggData, ok := vulnAgg.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						if vuln, ok := bucketData["key"].(string); ok {
							if docCount, ok := bucketData["doc_count"].(float64); ok {
								results = append(results, domain_overview.TotalBugStatusItem{
									FindingsName:  vuln,
									FindingsTotal: int64(docCount),
								})
								total += int64(docCount)
							}
						}
					}
				}
			}
		}
	}

	// Sort berdasarkan total count (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].FindingsTotal > results[j].FindingsTotal
	})

	// Set ID setelah sorting
	for i := range results {
		results[i].ID = fmt.Sprintf("%d", i+1)
	}

	return &domain_overview.ResponseTotalBugStatusItem{
		TotalData: total,
		ListData:  results,
	}, nil
}
func (r *SecurityCheklistRepo) executeQuery(ctx context.Context, query map[string]interface{}) (*domain.SearchResponse, error) {
	// Convert query ke JSON
	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}
	// Eksekusi search request
	req := esapi.SearchRequest{
		Index: []string{"proxy-traffic-new"}, // langsung hardcode di sini
		Body:  strings.NewReader(string(queryBytes)),
	}

	res, err := req.Do(ctx, r.client)
	if err != nil {
		return nil, fmt.Errorf("failed to execute search request: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		fmt.Println(res)
		return nil, fmt.Errorf("elasticsearch error: %s", res.Status())
	}

	// Parse response
	var response domain.SearchResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {

		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// GetSecurityChecklistDetailByID retrieves detailed information for a specific security checklist item
func (s *SecurityCheklistRepo) GetSecurityChecklistDetailByID(ctx context.Context, id string) (*domain_overview.DetailIdSecurityChecklistItem, error) {
	query := s.buildSecurityChecklistDetailQuery(id)
	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute security checklist detail query: %w", err)
	}
	return s.parseSecurityChecklistDetail(response)
}

func (s *SecurityCheklistRepo) buildSecurityChecklistDetailQuery(id string) map[string]interface{} {
	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"term": map[string]interface{}{
							"_id": id,
						},
					},
				},
			},
		},
	}

	return query
}

func (s *SecurityCheklistRepo) parseSecurityChecklistDetail(response *domain.SearchResponse) (*domain_overview.DetailIdSecurityChecklistItem, error) {
	if len(response.Hits.Hits) == 0 {
		return nil, fmt.Errorf("security checklist item not found")
	}

	hit := response.Hits.Hits[0]
	doc := hit.Source

	// Parse time untuk display
	parsedTime := s.formatToIndonesianShort(doc.Time)

	// Generate key berdasarkan timestamp atau bisa menggunakan logic lain
	key := "1" // atau bisa generate berdasarkan index/timestamp

	// Generate HashID (bisa menggunakan logic yang sama seperti di table atau custom)
	hashID := fmt.Sprintf("%d", 1583) // atau generate berdasarkan logic tertentu

	detail := &domain_overview.DetailIdSecurityChecklistItem{
		Key:           key,
		ID:            doc.ID,
		DateTime:      parsedTime,
		HashID:        hashID,
		Host:          doc.Host,
		Method:        doc.Method,
		StatusCode:    doc.StatusCode,
		Tools:         doc.Tools,
		URL:           doc.URL,
		PentesterIP:   doc.IP,
		Severity:      util_uuid.Capitalize(doc.Severity),
		Status:        util_uuid.Capitalize(doc.Status),
		Validation:    util_uuid.Capitalize(doc.Validation),
		Vulnerability: doc.Vulnerability,
		Request:       doc.Request,  // Field tambahan untuk detail
		Response:      doc.Response, // Field tambahan untuk detail
	}

	return detail, nil
}

// Alternative method if you want to search by document ID in Elasticsearch
func (s *SecurityCheklistRepo) GetSecurityChecklistDetailByESID(ctx context.Context, esID string) (*domain_overview.DetailIdSecurityChecklistItem, error) {
	query := map[string]interface{}{
		"size": 1,
		"query": map[string]interface{}{
			"ids": map[string]interface{}{
				"values": []string{esID},
			},
		},
	}

	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute security checklist detail query by ES ID: %w", err)
	}

	return s.parseSecurityChecklistDetail(response)
}

func (s *SecurityCheklistRepo) GetURLList(ctx context.Context, flagDomain string, params domain_overview.URLListParams) (*domain_overview.URLListResponse, error) {
	// Set default page if not provided
	if params.Page < 1 {
		params.Page = 1
	}
	// Pastikan limit > 0
	if params.Limit <= 0 {
		params.Limit = 5
	}

	// Build the aggregation query
	query := s.buildURLListQuery(flagDomain, params)

	// Execute the query
	response, err := s.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute URL list query: %w", err)
	}

	// Parse the response
	return s.parseURLListResponse(response, params)
}

// buildURLListQuery creates the Elasticsearch query for getting URL list
func (s *SecurityCheklistRepo) buildURLListQuery(flagDomain string, params domain_overview.URLListParams) map[string]interface{} {
	const pageSize = 5 // Fixed page size for infinite scroll

	mustClauses := []map[string]interface{}{}

	// Filter by flag domain if provided
	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	// Add search filter if provided
	var searchFilter map[string]interface{}
	if params.Search != "" {
		searchFilter = map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					// Exact match - highest priority
					{
						"term": map[string]interface{}{
							"url.keyword": map[string]interface{}{
								"value": params.Search,
								"boost": 3.0,
							},
						},
					},
					// Prefix match - medium priority
					{
						"prefix": map[string]interface{}{
							"url.keyword": map[string]interface{}{
								"value": params.Search,
								"boost": 2.0,
							},
						},
					},
					// Wildcard match - lowest priority
					{
						"wildcard": map[string]interface{}{
							"url.keyword": map[string]interface{}{
								"value": fmt.Sprintf("*%s*", strings.ToLower(params.Search)),
								"boost": 1.0,
							},
						},
					},
				},
				"minimum_should_match": 1,
			},
		}
	}
	// Calculate offset for pagination
	offset := (params.Page - 1) * pageSize

	// Build the main query
	query := map[string]interface{}{
		"size": 0, // We don't need individual documents, only aggregations
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": mustClauses,
			},
		},
		"aggs": map[string]interface{}{
			"urls": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "url.keyword",
					"size":  offset + pageSize + 1, // Get extra to check if there's more
					"order": map[string]interface{}{
						"_count": "desc", // Sort by count descending
					},
				},
			},
		},
	}

	// Add search filter to aggregation if provided
	if searchFilter != nil {
		query["aggs"].(map[string]interface{})["urls"].(map[string]interface{})["terms"].(map[string]interface{})["include"] = fmt.Sprintf(".*%s.*", strings.ToLower(params.Search))
	}

	// If search is provided, also add it to the main query
	if searchFilter != nil {
		mustClauses = append(mustClauses, searchFilter)
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = mustClauses
	}

	log.Printf("URL List Query: page=%d, search='%s', offset=%d", params.Page, params.Search, offset)

	return query
}

func (s *SecurityCheklistRepo) parseURLListResponse(response *domain.SearchResponse, params domain_overview.URLListParams) (*domain_overview.URLListResponse, error) {
	const pageSize = 5

	result := &domain_overview.URLListResponse{
		Data: []domain_overview.URLItem{},
		Pagination: domain_overview.PaginationInfo{
			Size:        pageSize,
			HasNext:     false,
			HasPrevious: false,
		},
	}

	// Check if aggregations exist
	if response.Aggregations == nil {
		return result, nil
	}

	// Extract URL aggregation
	urlsAggInterface, ok := response.Aggregations["urls"]
	if !ok {
		return result, nil
	}

	urlsAgg, ok := urlsAggInterface.(map[string]interface{})
	if !ok {
		return result, nil
	}

	bucketsInterface, ok := urlsAgg["buckets"]
	if !ok {
		return result, nil
	}

	buckets, ok := bucketsInterface.([]interface{})
	if !ok {
		return result, nil
	}

	// Calculate pagination
	offset := (params.Page - 1) * pageSize
	totalBuckets := len(buckets)

	// Pagination flags
	result.Pagination.HasPrevious = params.Page > 1
	result.Pagination.HasNext = offset+pageSize < totalBuckets

	// Get the URLs for current page
	endIdx := offset + pageSize
	if endIdx > totalBuckets {
		endIdx = totalBuckets
	}

	if offset < totalBuckets {
		for i := offset; i < endIdx; i++ {
			bucket, ok := buckets[i].(map[string]interface{})
			if !ok {
				continue
			}

			url, ok := bucket["key"].(string)
			if !ok {
				continue
			}

			count, ok := bucket["doc_count"].(float64)
			if !ok {
				continue
			}

			result.Data = append(result.Data, domain_overview.URLItem{
				URL:   url,
				Count: int64(count),
			})
		}
	}

	return result, nil
}

func NewSecurityCheklistRepo(client *elasticsearch.Client) domain.SecurityChecklistRepository {
	return &SecurityCheklistRepo{
		client: client,
	}
}
func removeDuplicateStrings(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	seen := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
