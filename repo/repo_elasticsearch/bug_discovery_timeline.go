package repo_elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"

	"xops-admin/domain"
	domain_overview "xops-admin/domain/user/overview"
	util_uuid "xops-admin/util/uuid"
)

type BugDiscoveryTimelineRepo struct {
	client *elasticsearch.Client
}

func NewBugDiscoveryTimelineRepo(client *elasticsearch.Client) domain.OverviewRepository {
	return &BugDiscoveryTimelineRepo{
		client: client,
	}
}

func (r *BugDiscoveryTimelineRepo) GetLogActivity(ctx context.Context, params domain_overview.LogActivityPaginationParams) (*domain_overview.LogActivityResponse, error) {
	var startDate, endDate time.Time
	var err error

	if params.StartDate != "" {
		startDate, err = time.Parse("2006-01-02", params.StartDate)
		if err != nil {
			return nil, fmt.Errorf("invalid start_date format: %w", err)
		}
	}

	if params.EndDate != "" {
		endDate, err = time.Parse("2006-01-02", params.EndDate)
		if err != nil {
			return nil, fmt.Errorf("invalid end_date format: %w", err)
		}
	} else {
		endDate = time.Now()
	}

	// Default domain
	domainName := params.Domain

	query := r.buildLogActivityQueryWithPagination(domainName, startDate, endDate, params)

	// DEBUG: Print the query being sent
	fmt.Printf("=== QUERY DEBUG ===\n")
	queryJSON, _ := json.MarshalIndent(query, "", "  ")
	fmt.Printf("Query: %s\n", string(queryJSON))
	fmt.Printf("==================\n")

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute log activity query: %w", err)
	}

	return r.parseLogActivityWithPagination(response, params)
}
func (r *BugDiscoveryTimelineRepo) buildLogActivityQueryWithPagination(domainName string, startDate, endDate time.Time, params domain_overview.LogActivityPaginationParams) map[string]interface{} {
	// Default range 1 bulan terakhir (kalau StartDate/EndDate kosong)
	startOfDay := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 0, 0, 0, 0, startDate.Location())
	endOfDay := time.Date(endDate.Year(), endDate.Month(), endDate.Day(), 23, 59, 59, 999999999, endDate.Location())

	startDateStr := startOfDay.Format("02/01/06 15:04")
	endDateStr := endOfDay.Format("02/01/06 15:04")

	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "pentester_name.keyword",
			},
		},
		{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte":    startDateStr,
					"lte":    endDateStr,
					"format": "dd/MM/yy HH:mm",
				},
			},
		},
	}

	// Filter domain
	if params.Domain != "" && params.Domain != "all" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": params.Domain,
			},
		})
	}

	if params.Search != "" {
		searchQuery := map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					// Exact matches (fastest) - higher boost score
					{
						"multi_match": map[string]interface{}{
							"query":  params.Search,
							"fields": []string{"pentester_name.keyword^2", "ip.keyword^2"},
							"type":   "phrase",
							"boost":  2.0,
						},
					},
					// Prefix matches (faster than full wildcard)
					{
						"multi_match": map[string]interface{}{
							"query":  params.Search,
							"fields": []string{"pentester_name", "ip"},
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
										"ip.keyword": fmt.Sprintf("*%s*", params.Search),
									},
								},
								{
									"wildcard": map[string]interface{}{
										"pentester_name.keyword": fmt.Sprintf("*%s*", params.Search),
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
	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"pentester_name.keyword": "-"}},
		{"term": map[string]interface{}{"pentester_name.keyword": ""}},
	}
	query := map[string]interface{}{
		"size": 0, // hanya ambil aggs, bukan hits
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must":     mustClauses,
				"must_not": mustNotClauses,
			},
		},
		"aggs": map[string]interface{}{
			"pentesters": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "pentester_name.keyword",
					"size":  1000,
				},
				"aggs": map[string]interface{}{
					"daily_activities": map[string]interface{}{
						"date_histogram": map[string]interface{}{
							"field":             "time",
							"calendar_interval": "1d",
							"format":            "dd/MM/yy HH:mm",
							"min_doc_count":     1,
							"order": map[string]interface{}{
								"_key": "desc", // DESC by time
							},
						},
						"aggs": map[string]interface{}{
							"start_time": map[string]interface{}{
								"min": map[string]interface{}{
									"field":  "time",
									"format": "dd/MM/yy HH:mm",
								},
							},
							"end_time": map[string]interface{}{
								"max": map[string]interface{}{
									"field":  "time",
									"format": "dd/MM/yy HH:mm",
								},
							},
							"ips": map[string]interface{}{
								"terms": map[string]interface{}{
									"field": "ip.keyword",
									"size":  5,
								},
							},
							"doc_id": map[string]interface{}{
								"top_hits": map[string]interface{}{
									"size": 1,
									"sort": []map[string]interface{}{
										{"time": map[string]interface{}{"order": "asc"}},
									},
									"_source": []string{"id"},
								},
							},
						},
					},
				},
			},
		},
	}

	return query
}

func (r *BugDiscoveryTimelineRepo) parseLogActivityWithPagination(
	response *domain.SearchResponse,
	params domain_overview.LogActivityPaginationParams,
) (*domain_overview.LogActivityResponse, error) {

	var allResults []domain_overview.LogActivity
	entryNo := 1

	pentesterAgg, ok := response.Aggregations["pentesters"]
	if !ok {
		return &domain_overview.LogActivityResponse{
			Data:       []domain_overview.LogActivity{},
			Pagination: domain_overview.PaginationInfo{Size: 0},
		}, nil
	}

	pentesterData, _ := pentesterAgg.(map[string]interface{})
	buckets, _ := pentesterData["buckets"].([]interface{})

	for _, bucket := range buckets {
		b, _ := bucket.(map[string]interface{})
		name, _ := b["key"].(string)

		if dailyAgg, ok := b["daily_activities"].(map[string]interface{}); ok {
			if dayBuckets, ok := dailyAgg["buckets"].([]interface{}); ok {
				for _, dayBucket := range dayBuckets {
					dayData, _ := dayBucket.(map[string]interface{})

					// doc_id
					var docID string
					if docIDAgg, ok := dayData["doc_id"].(map[string]interface{}); ok {
						if hits, ok := docIDAgg["hits"].(map[string]interface{}); ok {
							if hitsArray, ok := hits["hits"].([]interface{}); ok && len(hitsArray) > 0 {
								if firstHit, ok := hitsArray[0].(map[string]interface{}); ok {
									if idVal, ok := firstHit["_id"].(string); ok {
										docID = idVal
									}
								}
							}
						}
					}

					// ips
					var ips []string
					if ipsAgg, ok := dayData["ips"].(map[string]interface{}); ok {
						if ipBuckets, ok := ipsAgg["buckets"].([]interface{}); ok {
							for _, ipBucket := range ipBuckets {
								if ipData, ok := ipBucket.(map[string]interface{}); ok {
									ip, _ := ipData["key"].(string)
									ips = append(ips, ip)
								}
							}
						}
					}

					// start & end
					var startDate, endDate string
					if startTimeAgg, ok := dayData["start_time"].(map[string]interface{}); ok {
						startDate, _ = startTimeAgg["value_as_string"].(string)
					}
					if endTimeAgg, ok := dayData["end_time"].(map[string]interface{}); ok {
						endDate, _ = endTimeAgg["value_as_string"].(string)
					}
					if endDate == "" {
						endDate = startDate
					}

					allResults = append(allResults, domain_overview.LogActivity{
						No:        strconv.Itoa(entryNo),
						Id:        docID,
						Name:      name,
						IPs:       strings.Join(ips, ", "),
						StartDate: r.formatToIndonesianShort(startDate),
						EndDate:   r.formatToIndonesianShort(endDate),
					})
					entryNo++
				}
			}
		}
	}

	// sudah DESC by time dari query → gak perlu sort lagi
	// kalau mau lebih aman, bisa sort ulang di sini

	return &domain_overview.LogActivityResponse{
		Data: allResults,
		Pagination: domain_overview.PaginationInfo{
			Size: len(allResults),
		},
	}, nil
}

func (r *BugDiscoveryTimelineRepo) formatToIndonesianShort(dateStr string) string {
	if dateStr == "" {
		return ""
	}

	parsedTime, err := time.Parse("02/01/06 15:04", dateStr)
	if err != nil {
		return dateStr
	}

	// Konversi ke WIB
	wibLocation, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		wibLocation = time.FixedZone("WIB", 7*60*60)
	}
	wibTime := parsedTime.In(wibLocation)

	shortMonthNames := map[time.Month]string{
		time.January:   "Jan",
		time.February:  "Feb",
		time.March:     "Mar",
		time.April:     "Apr",
		time.May:       "Mei",
		time.June:      "Jun",
		time.July:      "Jul",
		time.August:    "Agu",
		time.September: "Sep",
		time.October:   "Okt",
		time.November:  "Nov",
		time.December:  "Des",
	}

	// Format: "3 Sep 2025, 10:31"
	return fmt.Sprintf("%d %s %d, %02d:%02d",
		wibTime.Day(),
		shortMonthNames[wibTime.Month()],
		wibTime.Year(),
		wibTime.Hour(),
		wibTime.Minute())
}

func (r *BugDiscoveryTimelineRepo) GetPentestersEffectiveness(ctx context.Context, domainName string, period int) ([]domain_overview.PentesterEffectiveness, error) {
	// Build query untuk mendapatkan data pentester dengan aktivitas terakhir

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{},
			},
		},
		"aggs": map[string]interface{}{
			"pentesters": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "pentester_name.keyword",
					"size":  100,
				},
				"aggs": map[string]interface{}{
					"total_findings": map[string]interface{}{
						"filter": map[string]interface{}{
							"terms": map[string]interface{}{
								"validation.keyword": []string{"FIXED", "PENDING"},
							},
						},
					},
					"latest_activity": map[string]interface{}{
						"top_hits": map[string]interface{}{
							"sort": []map[string]interface{}{
								{
									"time": map[string]interface{}{
										"order": "desc",
									},
								},
							},
							"size":    1,
							"_source": []string{"time", "ip", "pentester_name"},
						},
					},
				},
			},
		},
	}

	// Add domain filter if specified
	if domainName != "" && domainName != "all" {
		mustQueries := query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"].([]map[string]interface{})
		domainQuery := map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain": domainName,
			},
		}
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["must"] = append(mustQueries, domainQuery)
	}

	queryBytes, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Execute search request
	req := esapi.SearchRequest{
		Index: []string{"proxy-traffic-new"}, // langsung hardcode di sini
		Body:  strings.NewReader(string(queryBytes)),
	}

	res, err := req.Do(ctx, r.client)
	if err != nil {
		return nil, fmt.Errorf("failed to execute search: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch error: %s", res.String())
	}

	// Parse response
	var searchResponse struct {
		Aggregations struct {
			Pentesters struct {
				Buckets []struct {
					Key           string `json:"key"`
					DocCount      int64  `json:"doc_count"`
					TotalFindings struct {
						DocCount int64 `json:"doc_count"`
					} `json:"total_findings"`
					LatestActivity struct {
						Hits struct {
							Hits []struct {
								Source struct {
									Time          string `json:"time"`
									IP            string `json:"ip"`
									PentesterName string `json:"pentester_name"`
								} `json:"_source"`
							} `json:"hits"`
						} `json:"hits"`
					} `json:"latest_activity"`
				} `json:"buckets"`
			} `json:"pentesters"`
		} `json:"aggregations"`
	}

	if err := json.NewDecoder(res.Body).Decode(&searchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process results dan tentukan status aktif
	var results []domain_overview.PentesterEffectiveness
	currentTime := time.Now()
	for i, bucket := range searchResponse.Aggregations.Pentesters.Buckets {
		pentester := domain_overview.PentesterEffectiveness{
			Key:          fmt.Sprintf("%d", i+1),
			Name:         bucket.Key,
			TotalFinding: int(bucket.TotalFindings.DocCount),
		}

		// Get latest activity data
		if len(bucket.LatestActivity.Hits.Hits) > 0 {
			latestHit := bucket.LatestActivity.Hits.Hits[0].Source
			pentester.IP = latestHit.IP

			// Parse time dari format yang ada di data
			// Assuming format: "25/08/25 08:40" (DD/MM/YY HH:MM)
			lastActivityTime, err := parseActivityTime(latestHit.Time)
			if err != nil {
				// Jika gagal parse, anggap tidak aktif
				pentester.IsActive = false
				pentester.Status.IsActive = false
				pentester.Status.Description = "Invalid time format"
				continue
			}

			pentester.LastActivity = lastActivityTime

			// Hitung selisih waktu dalam menit
			timeDiff := currentTime.Sub(lastActivityTime)
			minutesSinceLastActivity := int(timeDiff.Minutes())

			// Tentukan status aktif (aktif jika aktivitas terakhir kurang dari 90 menit)
			if minutesSinceLastActivity < 90 {
				pentester.IsActive = true
				pentester.Status.IsActive = true
				formattedTime := lastActivityTime.Format("Mon, 02 Jan 2006 15.04")
				pentester.Status.Description = formattedTime
			} else {
				pentester.IsActive = false
				pentester.Status.IsActive = false
				formattedTime := lastActivityTime.Format("Mon, 02 Jan 2006 15.04")
				pentester.Status.Description = formattedTime
			}
		} else {
			// Tidak ada aktivitas
			pentester.IsActive = false
			pentester.Status.IsActive = false
			pentester.Status.Description = "No recent activity"
		}

		results = append(results, pentester)
	}

	return results, nil
}

// GetPentestersActivity implements domain.ProxyTrafficRepository.
func (r *BugDiscoveryTimelineRepo) GetPentestersActivity(ctx context.Context, domainName string, period int) ([]domain_overview.PentesterActivity, error) {
	query := r.buildPentesterActivityQuery(domainName, period)
	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute pentester activity query: %w", err)
	}
	return r.parsePentesterActivity(response, period)
}

// Existing function - Chart 1
func (r *BugDiscoveryTimelineRepo) GetVulnerabilityStats(ctx context.Context, days int, domainName, filter string) ([]domain_overview.VulnStat, error) {
	query := r.buildVulnerabilityStatsQuery(days, domainName, filter)

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	return r.parseVulnerabilityStats(response, days)
}

// NEW: Chart 2 - Bug Severity Distribution
func (r *BugDiscoveryTimelineRepo) GetBugSeverityDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.SeverityDistribution, error) {
	query := r.buildSeverityDistributionQuery(domainName, period, status)
	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute severity distribution query: %w", err)
	}
	return r.parseSeverityDistribution(response)
}

// NEW: Chart 2 - Bug Status Distribution
func (r *BugDiscoveryTimelineRepo) GetBugStatusDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.StatusDistribution, error) {
	query := r.buildStatusDistributionQuery(domainName, period, status)

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute status distribution query: %w", err)
	}

	return r.parseStatusDistribution(response)
}

// NEW: Chart 2 - Bug Validation Distribution
func (r *BugDiscoveryTimelineRepo) GetBugValidationDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.ValidationDistribution, error) {
	query := r.buildValidationDistributionQuery(domainName, period, status)

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute validation distribution query: %w", err)
	}

	return r.parseValidationDistribution(response)
}

// NEW: Chart 3 - Host/Domain Bugs Exposure
func (r *BugDiscoveryTimelineRepo) GetHostBugsExposure(ctx context.Context, domainName string, period int) ([]domain_overview.HostExposure, error) {
	query := r.buildHostExposureQuery(domainName, period)

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute host exposure query: %w", err)
	}

	return r.parseHostExposure(response)
}

// NEW: Chart 4 - Bug Type Frequency
func (r *BugDiscoveryTimelineRepo) GetBugTypeFrequency(ctx context.Context, domainName string, period int) ([]domain_overview.BugTypeFrequency, error) {
	query := r.buildBugTypeFrequencyQuery(domainName, period)

	response, err := r.executeQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute bug type frequency query: %w", err)
	}

	return r.parseBugTypeFrequency(response)
}

// ========= QUERY BUILDERS =========

func (r *BugDiscoveryTimelineRepo) buildSeverityDistributionQuery(flagDomain string, period int, status string) map[string]interface{} {
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

	// Add domain filter if provided
	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	// Add status filter if specified
	// Empty string ("") means show all statuses (no filter)
	// Any non-empty value means filter by that specific status
	if status != "" && strings.ToLower(status) != "all" {
		statusFilter := map[string]interface{}{
			"term": map[string]interface{}{
				"status.keyword": strings.ToUpper(status), // Filter by status field, not severity
			},
		}
		mustClauses = append(mustClauses, statusFilter)
	}

	// Add time period filter if specified (period > 0 means filter, 0 or empty means all time)
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd/d", period), // Added /d for start of day
					"lte": "now/d",                          // Added /d for end of day
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
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
			"severity_distribution": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity.keyword",
					"size":  1000, // top 20 severity buckets
					"order": map[string]interface{}{
						"_count": "desc", // Order by count descending
					},
				},
				"aggs": map[string]interface{}{
					"urls_breakdown": map[string]interface{}{
						"terms": map[string]interface{}{
							"field": "url.keyword",
							"size":  2147483647, // Maximum possible size (no limit)
							"order": map[string]interface{}{
								"_count": "desc",
							},
						},
					},
				},
			},
		},
	}
}
func (r *BugDiscoveryTimelineRepo) buildStatusDistributionQuery(flagDomain string, period int, status string) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "status.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"status.keyword": []string{"SUCCESS", "NEUTRAL", "FAILED"},
			},
		},
	}

	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}
	// Add status filter if specified (empty string or "all" means no filter)
	if status != "" && strings.ToLower(status) != "all" {
		statusFilter := map[string]interface{}{
			"term": map[string]interface{}{
				"status.keyword": strings.ToUpper(status), // Assuming status is stored in uppercase
			},
		}
		mustClauses = append(mustClauses, statusFilter)
	}

	// Add time period filter if specified (period > 0 means filter, 0 means all time)
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd", period),
					"lte": "now",
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"status.keyword": "-"}},
		{"term": map[string]interface{}{"status.keyword": ""}},
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
			"status_distribution": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "status.keyword",
					"size":  20,
				},
				"aggs": map[string]interface{}{
					"vulnerability_breakdown": map[string]interface{}{
						"terms": map[string]interface{}{
							"field": "vulnerability.keyword",
							"size":  1000,
						},
					},
				},
			},
		},
	}
}

func (r *BugDiscoveryTimelineRepo) buildValidationDistributionQuery(flagDomain string, period int, status string) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "validation.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"validation.keyword": []string{"FIXED", "VALIDATED", "PENDING"},
			},
		},
	}

	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	// Add status filter if specified (empty string or "all" means no filter)
	if status != "" && strings.ToLower(status) != "all" {
		statusFilter := map[string]interface{}{
			"term": map[string]interface{}{
				"validation.keyword": strings.ToUpper(status), // Assuming status is stored in uppercase
			},
		}
		mustClauses = append(mustClauses, statusFilter)
	}

	// Add time period filter if specified (period > 0 means filter, 0 means all time)
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd", period),
					"lte": "now",
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"validation.keyword": "-"}},
		{"term": map[string]interface{}{"validation.keyword": ""}},
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
			"validation_distribution": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "validation.keyword",
					"size":  20,
				},
				"aggs": map[string]interface{}{
					"vulnerability_breakdown": map[string]interface{}{
						"terms": map[string]interface{}{
							"field": "vulnerability.keyword",
							"size":  1000,
						},
					},
				},
			},
		},
	}
}

func (r *BugDiscoveryTimelineRepo) buildHostExposureQuery(flagDomain string, period int) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "vulnerability.keyword",
			},
		},
		{
			"exists": map[string]interface{}{
				"field": "host.keyword",
			},
		},
	}

	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}
	// Add time period filter if specified (period > 0 means filter, 0 means all time)
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd", period),
					"lte": "now",
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"vulnerability.keyword": "-"}},
		{"term": map[string]interface{}{"vulnerability.keyword": ""}},
		{"term": map[string]interface{}{"host.keyword": "-"}},
		{"term": map[string]interface{}{"host.keyword": ""}},
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
			"host_exposure": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "host.keyword",
					"size":  10000,
				},
			},
		},
	}
}

// Simplified working hours calculation with session-based approach
func (r *BugDiscoveryTimelineRepo) buildPentesterActivityQuery(flagDomain string, period int) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "pentester_name.keyword",
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

	// Add time period filter if specified (0 = all time, 7 = last 7 days, 30 = last 30 days)
	if period > 0 {
		mustClauses = append(mustClauses, map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd/d", period),
					"lte": "now/d",
				},
			},
		})
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"pentester_name.keyword": "-"}},
		{"term": map[string]interface{}{"pentester_name.keyword": ""}},
	}

	// Determine aggregation name based on period
	var workingHoursAggName string
	switch period {
	case 7:
		workingHoursAggName = "weekly_working_hours"
	case 30:
		workingHoursAggName = "monthly_working_hours"
	default: // 0 or any other value = all time
		workingHoursAggName = "total_working_hours"
	}

	// Use Indonesia timezone
	indonesiaTimezone := "Asia/Jakarta"

	return map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must":     mustClauses,
				"must_not": mustNotClauses,
			},
		},
		"aggs": map[string]interface{}{
			"pentester_activity": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "pentester_name.keyword",
					"size":  20,
				},
				"aggs": map[string]interface{}{
					"unique_days": map[string]interface{}{
						"cardinality": map[string]interface{}{
							"script": fmt.Sprintf("doc['time'].size() > 0 ? doc['time'].value.toInstant().atZone(java.time.ZoneId.of(\"%s\")).toLocalDate().toString() : null", indonesiaTimezone),
						},
					},

					workingHoursAggName: map[string]interface{}{
						"scripted_metric": map[string]interface{}{
							"init_script": "state.dailyActivities = new HashMap()",

							"map_script": fmt.Sprintf(`
								if (doc['time'].size() > 0) { 
									def dt = doc['time'].value;
									def zonedDt = dt.toInstant().atZone(java.time.ZoneId.of("%s"));
									def day = zonedDt.toLocalDate().toString();
									def totalMinutes = zonedDt.getHour() * 60 + zonedDt.getMinute();
									
									if (!state.dailyActivities.containsKey(day)) { 
										def activities = new ArrayList();
										activities.add(totalMinutes);
										state.dailyActivities.put(day, activities); 
									} else { 
										def activities = state.dailyActivities.get(day);
										activities.add(totalMinutes);
									} 
								}
							`, indonesiaTimezone),

							"combine_script": "return state.dailyActivities",

							"reduce_script": `
								def allDailyActivities = new HashMap(); 
								def maxGapMinutes = 90; // 90 minutes gap threshold
								
								// Combine all activities from all shards
								for (s in states) { 
									for (entry in s.entrySet()) { 
										def day = entry.getKey(); 
										def activities = entry.getValue(); 
										if (!allDailyActivities.containsKey(day)) { 
											allDailyActivities.put(day, new ArrayList(activities)); 
										} else { 
											allDailyActivities.get(day).addAll(activities);
										} 
									} 
								}
								
								def totalMinutes = 0; 
								
								// Process each day's activities
								for (entry in allDailyActivities.entrySet()) { 
									def activities = entry.getValue(); 
									
									// Sort activities by time
									Collections.sort(activities);
									
									if (activities.size() == 1) {
										// If only one activity, count as 30 minutes minimum
										totalMinutes += 30;
									} else if (activities.size() > 1) {
										def sessions = new ArrayList();
										def sessionStart = activities.get(0);
										def sessionEnd = activities.get(0);
										
										// Group activities into sessions based on 90-minute gap
										for (int i = 1; i < activities.size(); i++) {
											def currentActivity = activities.get(i);
											def gap = currentActivity - sessionEnd;
											
											if (gap <= maxGapMinutes) {
												// Continue current session
												sessionEnd = currentActivity;
											} else {
												// Gap is more than 90 minutes, close current session and start new one
												def sessionDuration = sessionEnd - sessionStart;
												if (sessionDuration == 0) {
													sessionDuration = 30; // Minimum 30 minutes for single activity sessions
												}
												sessions.add(sessionDuration);
												
												// Start new session
												sessionStart = currentActivity;
												sessionEnd = currentActivity;
											}
										}
										
										// Add the last session
										def lastSessionDuration = sessionEnd - sessionStart;
										if (lastSessionDuration == 0) {
											lastSessionDuration = 30; // Minimum 30 minutes
										}
										sessions.add(lastSessionDuration);
										
										// Sum all session durations
										for (sessionDuration in sessions) {
											totalMinutes += sessionDuration;
										}
									}
								}
								
								return totalMinutes;
							`,
						},
					},

					"avg_daily_working_hours": map[string]interface{}{
						"scripted_metric": map[string]interface{}{
							"init_script": "state.dailyActivities = new HashMap()",

							"map_script": fmt.Sprintf(`
								if (doc['time'].size() > 0) { 
									def dt = doc['time'].value;
									def zonedDt = dt.toInstant().atZone(java.time.ZoneId.of("%s"));
									def day = zonedDt.toLocalDate().toString();
									def totalMinutes = zonedDt.getHour() * 60 + zonedDt.getMinute();
									
									if (!state.dailyActivities.containsKey(day)) { 
										def activities = new ArrayList();
										activities.add(totalMinutes);
										state.dailyActivities.put(day, activities); 
									} else { 
										def activities = state.dailyActivities.get(day);
										activities.add(totalMinutes);
									} 
								}
							`, indonesiaTimezone),

							"combine_script": "return state.dailyActivities",

							"reduce_script": `
								def allDailyActivities = new HashMap(); 
								def maxGapMinutes = 90; // 90 minutes gap threshold
								
								// Combine all activities from all shards
								for (s in states) { 
									for (entry in s.entrySet()) { 
										def day = entry.getKey(); 
										def activities = entry.getValue(); 
										if (!allDailyActivities.containsKey(day)) { 
											allDailyActivities.put(day, new ArrayList(activities)); 
										} else { 
											allDailyActivities.get(day).addAll(activities);
										} 
									} 
								}
								
								def totalDailyMinutes = 0; 
								def activeDays = 0; 
								
								// Process each day's activities
								for (entry in allDailyActivities.entrySet()) { 
									def activities = entry.getValue(); 
									def dailyMinutes = 0;
									
									// Sort activities by time
									Collections.sort(activities);
									
									if (activities.size() == 1) {
										// If only one activity, count as 30 minutes minimum
										dailyMinutes = 30;
									} else if (activities.size() > 1) {
										def sessions = new ArrayList();
										def sessionStart = activities.get(0);
										def sessionEnd = activities.get(0);
										
										// Group activities into sessions based on 90-minute gap
										for (int i = 1; i < activities.size(); i++) {
											def currentActivity = activities.get(i);
											def gap = currentActivity - sessionEnd;
											
											if (gap <= maxGapMinutes) {
												// Continue current session
												sessionEnd = currentActivity;
											} else {
												// Gap is more than 90 minutes, close current session and start new one
												def sessionDuration = sessionEnd - sessionStart;
												if (sessionDuration == 0) {
													sessionDuration = 30; // Minimum 30 minutes for single activity sessions
												}
												sessions.add(sessionDuration);
												
												// Start new session
												sessionStart = currentActivity;
												sessionEnd = currentActivity;
											}
										}
										
										// Add the last session
										def lastSessionDuration = sessionEnd - sessionStart;
										if (lastSessionDuration == 0) {
											lastSessionDuration = 30; // Minimum 30 minutes
										}
										sessions.add(lastSessionDuration);
										
										// Sum all session durations for this day
										for (sessionDuration in sessions) {
											dailyMinutes += sessionDuration;
										}
									}
									
									if (dailyMinutes > 0) { 
										totalDailyMinutes += dailyMinutes; 
										activeDays++; 
									} 
								}
								
								return activeDays > 0 ? totalDailyMinutes / activeDays : 0;
							`,
						},
					},
				},
			},
		},
	}
}

// Helper function remains the same
func formatWorkingHours(totalMinutes float64) string {
	wholeHours := int(totalMinutes) / 60
	minutes := int(totalMinutes) % 60
	return fmt.Sprintf("%d hrs %d mins", wholeHours, minutes)
}

func (r *BugDiscoveryTimelineRepo) parsePentesterActivity(response *domain.SearchResponse, period int) ([]domain_overview.PentesterActivity, error) {
	var result []domain_overview.PentesterActivity
	if response.Aggregations == nil {
		return result, nil
	}

	pentesterAgg, ok := response.Aggregations["pentester_activity"]
	if !ok {
		return result, nil
	}

	pentesterData, ok := pentesterAgg.(map[string]interface{})
	if !ok {
		return result, nil
	}

	buckets, ok := pentesterData["buckets"].([]interface{})
	if !ok {
		return result, nil
	}

	colors := []string{"#10B981", "#3B82F6", "#F59E0B", "#EF4444", "#8B5CF6", "#06B6D4", "#84CC16", "#F97316"}

	// Tentukan key aggregation sesuai period
	var workingAggKey string
	switch period {
	case 7:
		workingAggKey = "weekly_working_hours"
	case 30:
		workingAggKey = "monthly_working_hours"
	default:
		workingAggKey = "total_working_hours"
	}

	for i, bucket := range buckets {
		b, ok := bucket.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := b["key"].(string)
		docCountFloat, ok := b["doc_count"].(float64)
		totalBugs := int64(0)
		if ok {
			totalBugs = int64(docCountFloat)
		}

		uniqueDays := int64(0)
		if uniqueAgg, ok := b["unique_days"].(map[string]interface{}); ok {
			if val, ok := uniqueAgg["value"].(float64); ok {
				uniqueDays = int64(val)
			}
		}

		avgDailyMinutes := 0.0
		if avgAgg, ok := b["avg_daily_working_hours"].(map[string]interface{}); ok {
			if val, ok := avgAgg["value"].(float64); ok {
				avgDailyMinutes = val
			}
		}

		weeklyMinutes := 0.0
		if workingAgg, ok := b[workingAggKey].(map[string]interface{}); ok {
			if val, ok := workingAgg["value"].(float64); ok {
				weeklyMinutes = val
			}
		}

		color := colors[i%len(colors)]

		result = append(result, domain_overview.PentesterActivity{
			Name:                name,
			Value:               totalBugs,
			Color:               color,
			PerDayWorkingHours:  formatWorkingHours(avgDailyMinutes),
			PerWeekWorkingHours: formatWorkingHours(weeklyMinutes),
			UniqueDays:          uniqueDays,
		})
	}

	return result, nil
}

func (r *BugDiscoveryTimelineRepo) buildBugTypeFrequencyQuery(flagDomain string, period int) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "vulnerability.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"validation.keyword": []string{"PENDING", "FIXED", "VALIDATED"},
			},
		},
	}

	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd", period),
					"lte": "now",
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"vulnerability.keyword": "-"}},
		{"term": map[string]interface{}{"vulnerability.keyword": ""}},
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
			"bug_type_frequency": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "vulnerability.keyword",
					"size":  50,
					"order": map[string]interface{}{
						"_count": "desc",
					},
				},
			},
		},
	}
}

func (r *BugDiscoveryTimelineRepo) buildVulnerabilityStatsQuery(period int, flagDomain, filter string) map[string]interface{} {
	mustClauses := []map[string]interface{}{
		{
			"exists": map[string]interface{}{
				"field": "vulnerability.keyword",
			},
		},
		{
			"terms": map[string]interface{}{
				"validation.keyword": []string{"PENDING", "FIXED", "VALIDATED"},
			},
		},
	}

	// Add domain filter if specified
	if flagDomain != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"flag_domain.keyword": flagDomain,
			},
		})
	}

	if filter != "" {
		mustClauses = append(mustClauses, map[string]interface{}{
			"term": map[string]interface{}{
				"severity.keyword": strings.ToUpper(filter),
			},
		})
	}

	// Add time range filter
	if period > 0 {
		timeFilter := map[string]interface{}{
			"range": map[string]interface{}{
				"time": map[string]interface{}{
					"gte": fmt.Sprintf("now-%dd/d", period), // /d untuk start of day
					"lte": "now/d",
				},
			},
		}
		mustClauses = append(mustClauses, timeFilter)
	}

	mustNotClauses := []map[string]interface{}{
		{"term": map[string]interface{}{"vulnerability.keyword": "-"}},
		{"term": map[string]interface{}{"vulnerability.keyword": ""}},
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
			"vulnerabilities_by_type": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "vulnerability.keyword",
					"size":  50,
					"order": map[string]interface{}{
						"_count": "desc",
					},
				},
				"aggs": map[string]interface{}{
					"daily_counts": map[string]interface{}{
						"date_histogram": map[string]interface{}{
							"field":             "time",
							"calendar_interval": "1d", // Changed from "interval": "day"
							"format":            "yyyy-MM-dd",
							"min_doc_count":     0,
							"extended_bounds": map[string]interface{}{
								"min": fmt.Sprintf("now-%dd/d", period),
								"max": "now/d",
							},
						},
					},
				},
			},
		},
	}
}

func (r *BugDiscoveryTimelineRepo) parseSeverityDistribution(response *domain.SearchResponse) ([]domain_overview.SeverityDistribution, error) {
	var result []domain_overview.SeverityDistribution
	colors := map[string]string{
		"Critical": "#e74c3c",
		"High":     "#f39c12",
		"Medium":   "#3498db",
		"Low":      "#2ecc71",
	}

	if aggs, ok := response.Aggregations["severity_distribution"]; ok {
		if aggData, ok := aggs.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for _, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						severity := bucketData["key"].(string)
						total := int64(bucketData["doc_count"].(float64))

						var hostsData []domain_overview.HostData
						// Changed from "hosts_breakdown" to "urls_breakdown"
						if urlsAgg, ok := bucketData["urls_breakdown"].(map[string]interface{}); ok {
							if urlBuckets, ok := urlsAgg["buckets"].([]interface{}); ok {
								for _, urlBucket := range urlBuckets {
									if urlData, ok := urlBucket.(map[string]interface{}); ok {
										urlPath := urlData["key"].(string)
										count := int64(urlData["doc_count"].(float64))

										hostsData = append(hostsData, domain_overview.HostData{
											Description:      urlPath, // Now contains full URL
											DescriptionTotal: count,
										})
									}
								}
							}
						}

						color, exists := colors[severity]
						if !exists {
							color = "#95a5a6" // default gray
						}
						result = append(result, domain_overview.SeverityDistribution{
							ID:          fmt.Sprintf("severity_%s", strings.ToLower(severity)),
							Name:        util_uuid.Capitalize(severity),
							StatusTotal: total,
							Color:       color,
							ListsData:   hostsData,
						})
					}
				}
			}
		}
	}

	// Sort by severity priority
	sort.Slice(result, func(i, j int) bool {
		priority := map[string]int{"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
		return priority[result[i].Name] < priority[result[j].Name]
	})

	return result, nil
}
func (r *BugDiscoveryTimelineRepo) parseStatusDistribution(response *domain.SearchResponse) ([]domain_overview.StatusDistribution, error) {
	var result []domain_overview.StatusDistribution
	colors := []string{"#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6", "#1abc9c"}

	if aggs, ok := response.Aggregations["status_distribution"]; ok {
		if aggData, ok := aggs.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for i, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						status := bucketData["key"].(string)
						total := int64(bucketData["doc_count"].(float64))

						var hostsData []domain_overview.HostData
						if hostsAgg, ok := bucketData["vulnerability_breakdown"].(map[string]interface{}); ok {
							if hostBuckets, ok := hostsAgg["buckets"].([]interface{}); ok {
								for _, hostBucket := range hostBuckets {
									if hostData, ok := hostBucket.(map[string]interface{}); ok {
										host := hostData["key"].(string)
										count := int64(hostData["doc_count"].(float64))
										hostsData = append(hostsData, domain_overview.HostData{
											Description:      host,
											DescriptionTotal: count,
										})
									}
								}
							}
						}

						color := colors[i%len(colors)]

						result = append(result, domain_overview.StatusDistribution{
							ID:          fmt.Sprintf("status_%s", strings.ToLower(status)),
							Name:        util_uuid.Capitalize(status),
							StatusTotal: total,
							Color:       color,
							ListsData:   hostsData,
						})
					}
				}
			}
		}
	}

	return result, nil
}

func (r *BugDiscoveryTimelineRepo) parseValidationDistribution(response *domain.SearchResponse) ([]domain_overview.ValidationDistribution, error) {
	var result []domain_overview.ValidationDistribution
	colors := []string{"#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6", "#1abc9c"}

	if aggs, ok := response.Aggregations["validation_distribution"]; ok {
		if aggData, ok := aggs.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for i, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						validation := bucketData["key"].(string)
						total := int64(bucketData["doc_count"].(float64))

						var hostsData []domain_overview.HostData
						if hostsAgg, ok := bucketData["vulnerability_breakdown"].(map[string]interface{}); ok {
							if hostBuckets, ok := hostsAgg["buckets"].([]interface{}); ok {
								for _, hostBucket := range hostBuckets {
									if hostData, ok := hostBucket.(map[string]interface{}); ok {
										host := hostData["key"].(string)
										count := int64(hostData["doc_count"].(float64))
										hostsData = append(hostsData, domain_overview.HostData{
											Description:      host,
											DescriptionTotal: count,
										})
									}
								}
							}
						}

						color := colors[i%len(colors)]

						result = append(result, domain_overview.ValidationDistribution{
							ID:          fmt.Sprintf("validation_%s", strings.ToLower(validation)),
							Name:        util_uuid.Capitalize(validation),
							StatusTotal: total,
							Color:       color,
							ListsData:   hostsData,
						})
					}
				}
			}
		}
	}

	return result, nil
}

func (r *BugDiscoveryTimelineRepo) parseHostExposure(response *domain.SearchResponse) ([]domain_overview.HostExposure, error) {
	var result []domain_overview.HostExposure
	colors := []string{"#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6", "#1abc9c", "#f1c40f", "#e67e22"}

	if aggs, ok := response.Aggregations["host_exposure"]; ok {
		if aggData, ok := aggs.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for i, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						host := bucketData["key"].(string)
						count := int64(bucketData["doc_count"].(float64))

						color := colors[i%len(colors)]

						result = append(result, domain_overview.HostExposure{
							Name:  host,
							Value: count,
							Color: color,
						})
					}
				}
			}
		}
	}

	return result, nil
}

func (r *BugDiscoveryTimelineRepo) parseBugTypeFrequency(response *domain.SearchResponse) ([]domain_overview.BugTypeFrequency, error) {
	var result []domain_overview.BugTypeFrequency
	colors := []string{"#FF8CAB", "#F4A5D2", "#FFBD84", "#64E4B1", "#6893FF", "#9b59b6", "#1abc9c", "#f1c40f"}

	if aggs, ok := response.Aggregations["bug_type_frequency"]; ok {
		if aggData, ok := aggs.(map[string]interface{}); ok {
			if buckets, ok := aggData["buckets"].([]interface{}); ok {
				for i, bucket := range buckets {
					if bucketData, ok := bucket.(map[string]interface{}); ok {
						bugType := bucketData["key"].(string)
						count := int64(bucketData["doc_count"].(float64))

						color := colors[i%len(colors)]

						result = append(result, domain_overview.BugTypeFrequency{
							Name:  bugType,
							Value: count,
							Color: color,
						})
					}
				}
			}
		}
	}

	return result, nil
}

// executeQuery mengeksekusi query ke BugDiscoveryTimeline
func (r *BugDiscoveryTimelineRepo) executeQuery(ctx context.Context, query map[string]interface{}) (*domain.SearchResponse, error) {
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

func (r *BugDiscoveryTimelineRepo) parseVulnerabilityStats(response *domain.SearchResponse, days int) ([]domain_overview.VulnStat, error) {
	var result []domain_overview.VulnStat

	// Check if the aggregation exists
	vulnerabilitiesAgg, ok := response.Aggregations["vulnerabilities_by_type"]
	if !ok {
		return result, fmt.Errorf("vulnerabilities_by_type aggregation not found")
	}

	// Parse the aggregation
	aggData, ok := vulnerabilitiesAgg.(map[string]interface{})
	if !ok {
		return result, fmt.Errorf("invalid aggregation data format")
	}

	// Get buckets
	buckets, ok := aggData["buckets"].([]interface{})
	if !ok {
		return result, fmt.Errorf("buckets not found in aggregation")
	}

	// Create date mapping for timeline
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days+1) // Adjust to include today
	dateToIndexMap := make(map[string]int)

	current := startDate
	for i := 0; i < days; i++ {
		dateKey := current.Format("2006-01-02") // Format matches ES response (yyyy-MM-dd)
		dateToIndexMap[dateKey] = i
		current = current.AddDate(0, 0, 1)
	}

	// Process each vulnerability type
	for _, bucket := range buckets {
		bucketData, ok := bucket.(map[string]interface{})
		if !ok {
			continue
		}

		// Get vulnerability type name
		vulnType, ok := bucketData["key"].(string)
		if !ok {
			continue
		}

		// Initialize daily data array with zeros
		dailyData := make([]int64, days)

		// Get daily counts
		dailyCounts, ok := bucketData["daily_counts"].(map[string]interface{})
		if !ok {
			continue
		}

		dailyBuckets, ok := dailyCounts["buckets"].([]interface{})
		if !ok {
			continue
		}

		// Process daily buckets
		for _, dailyBucket := range dailyBuckets {
			dailyBucketData, ok := dailyBucket.(map[string]interface{})
			if !ok {
				continue
			}

			// Get date and count
			dateStr, ok := dailyBucketData["key_as_string"].(string)
			if !ok {
				continue
			}

			count, ok := dailyBucketData["doc_count"].(float64)
			if !ok {
				continue
			}

			// Map to timeline index
			if dayIndex, exists := dateToIndexMap[dateStr]; exists {
				if dayIndex >= 0 && dayIndex < days {
					dailyData[dayIndex] = int64(count)
				}
			}
		}

		// Sample data to get exactly 7 data points
		sampledData := r.sampleDataTo7Days(dailyData, days)

		// Add to result
		result = append(result, domain_overview.VulnStat{
			Name: vulnType,
			Data: sampledData, // Now contains 7 sampled data points
		})
	}

	return result, nil
}

// Helper function to sample data into exactly 7 data points
func (r *BugDiscoveryTimelineRepo) sampleDataTo7Days(dailyData []int64, originalDays int) []int64 {
	targetDays := 7
	sampledData := make([]int64, targetDays)

	if originalDays <= targetDays {
		// If we have 7 or fewer days, just pad with zeros if needed
		copy(sampledData, dailyData)
		return sampledData
	}

	// Group consecutive days and sum them
	groupSize := originalDays / targetDays // Base group size
	remainder := originalDays % targetDays // Extra days to distribute

	startIndex := 0
	for i := 0; i < targetDays; i++ {
		// Calculate how many days in this group
		daysInGroup := groupSize
		if i < remainder {
			daysInGroup++ // Add extra day to first 'remainder' groups
		}

		// Sum all days in this group
		sum := int64(0)
		for j := 0; j < daysInGroup && startIndex < originalDays; j++ {
			sum += dailyData[startIndex]
			startIndex++
		}

		sampledData[i] = sum
	}

	return sampledData
}
func (r *BugDiscoveryTimelineRepo) GetTotalFindingsWithTrend(
	ctx context.Context,
	domainName string,
) (*domain_overview.ResponseTotalFindings, error) {
	now := time.Now()
	weekAgo := now.AddDate(0, 0, -7)
	twoWeeksAgo := now.AddDate(0, 0, -14)

	// === Query all time (untuk total) ===
	allTimeQuery := buildAllTimeFindingsQuery(domainName)
	allTimeData, err := r.executeFindingsQuery(ctx, allTimeQuery, "all_time")
	if err != nil {
		return nil, fmt.Errorf("error fetching all time data: %w", err)
	}

	// === Query minggu ini ===
	currentWeekQuery := buildFindingsQuery(domainName, weekAgo, now)
	currentWeekData, err := r.executeFindingsQuery(ctx, currentWeekQuery, "current_week")
	if err != nil {
		return nil, fmt.Errorf("error fetching current week data: %w", err)
	}

	// === Query minggu lalu ===
	lastWeekQuery := buildFindingsQuery(domainName, twoWeeksAgo, weekAgo)
	lastWeekData, err := r.executeFindingsQuery(ctx, lastWeekQuery, "last_week")
	if err != nil {
		return nil, fmt.Errorf("error fetching last week data: %w", err)
	}

	// === Hitung trend ===
	trendData := calculateTrendData(allTimeData, currentWeekData, lastWeekData)

	// === Hitung total all time ===
	var total int64
	for _, count := range allTimeData {
		total += int64(count)
	}

	return &domain_overview.ResponseTotalFindings{
		TotalData: total,
		ListData:  trendData,
	}, nil
}

func buildAllTimeFindingsQuery(domainName string) map[string]interface{} {
	return map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{
						"terms": map[string]interface{}{
							"validation.keyword": []interface{}{"FIXED", "VALIDATED", "PENDING"},
						},
					},
					map[string]interface{}{
						"term": map[string]interface{}{
							"flag_domain.keyword": domainName,
						},
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"severity_counts": map[string]interface{}{
				"terms": map[string]interface{}{
					"field":   "severity.keyword",
					"size":    1000,
					"missing": "Unknown",
				},
			},
		},
	}
}

// buildFindingsQuery membangun Elasticsearch query dengan perbaikan
func buildFindingsQuery(domainName string, startTime, endTime time.Time) map[string]interface{} {
	// Gunakan format yang sama persis dengan data
	startTimeStr := startTime.Format("02/01/06 15:04")
	endTimeStr := endTime.Format("02/01/06 15:04")

	query := map[string]interface{}{
		"size": 0,
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []interface{}{
					map[string]interface{}{
						"range": map[string]interface{}{
							"time": map[string]interface{}{
								"gte":    startTimeStr,
								"lte":    endTimeStr,
								"format": "dd/MM/yy HH:mm",
							},
						},
					},
					map[string]interface{}{
						"terms": map[string]interface{}{
							"validation.keyword": []interface{}{"FIXED", "VALIDATED", "PENDING"},
						},
					},
					map[string]interface{}{
						"term": map[string]interface{}{
							"flag_domain.keyword": domainName,
						},
					},
				},
			},
		},
		"aggs": map[string]interface{}{
			"severity_counts": map[string]interface{}{
				"terms": map[string]interface{}{
					"field":   "severity.keyword",
					"size":    1000,
					"missing": "Unknown",
				},
			},
			"validation_values": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "validation.keyword",
					"size":  1000,
				},
			},
			"debug_severity_values": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "severity.keyword",
					"size":  1000,
				},
			},
		},
	}

	return query
}

// calculateTrendData sekarang butuh allTimeData juga
func calculateTrendData(allTime, currentWeek, lastWeek map[string]int) []domain_overview.TotalFindingsCount {
	severityMapping := map[string]string{
		"CRITICAL":    "Critical",
		"HIGH":        "High",
		"MEDIUM":      "Medium",
		"LOW":         "Low",
		"INFORMATION": "Information",
	}
	severities := []string{"Critical", "High", "Medium", "Low", "Information"}

	var results []domain_overview.TotalFindingsCount

	for i, severity := range severities {
		currentCount := 0
		lastCount := 0
		allTimeCount := 0

		for dataKey, mappedSeverity := range severityMapping {
			if mappedSeverity == severity {
				if count, exists := currentWeek[dataKey]; exists {
					currentCount += count
				}
				if count, exists := lastWeek[dataKey]; exists {
					lastCount += count
				}
				if count, exists := allTime[dataKey]; exists {
					allTimeCount += count
				}
			}
		}

		// Juga cek exact match
		if count, exists := currentWeek[severity]; exists {
			currentCount += count
		}
		if count, exists := lastWeek[severity]; exists {
			lastCount += count
		}
		if count, exists := allTime[severity]; exists {
			allTimeCount += count
		}
		// Hitung tren
		var trendStatus, trendSum string
		if lastCount == 0 {
			if currentCount > 0 {
				trendStatus = "Up"
				trendSum = "100%"
			} else {
				trendStatus = "Neutral"
				trendSum = "0%"
			}
		} else {
			change := float64(currentCount-lastCount) / float64(lastCount) * 100
			fmt.Println(change)
			if change > 0 {
				trendStatus = "Up"
				trendSum = fmt.Sprintf("%.0f%%", change)
			} else if change < 0 {
				trendStatus = "Down"
				trendSum = fmt.Sprintf("%.0f%%", -change)
			} else {
				trendStatus = "Neutral"
				trendSum = "0%"
			}
		}

		results = append(results, domain_overview.TotalFindingsCount{
			ID:          fmt.Sprintf("%d", i+1),
			Severity:    severity,
			Total:       allTimeCount,
			TrendStatus: trendStatus,
			TrendSum:    trendSum,
		})
	}

	return results
}

// executeFindingsQuery - tambahkan debug info yang lebih lengkap
func (r *BugDiscoveryTimelineRepo) executeFindingsQuery(ctx context.Context, query map[string]interface{}, queryType string) (map[string]int, error) {
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("error marshaling query: %w", err)
	}

	res, err := r.client.Search(
		r.client.Search.WithContext(ctx),
		r.client.Search.WithIndex("proxy-traffic-new"),
		r.client.Search.WithBody(strings.NewReader(string(queryJSON))),
		r.client.Search.WithTrackTotalHits(true),
	)
	if err != nil {
		return nil, fmt.Errorf("error executing search: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		bodyBytes, _ := io.ReadAll(res.Body)
		fmt.Printf("Elasticsearch error response: %s\n", string(bodyBytes))
		return nil, fmt.Errorf("elasticsearch error: %s", res.String())
	}

	// Parse response dengan debug aggregations
	var searchResp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			SeverityCounts struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"severity_counts"`
			ValidationValues struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"validation_values"`
			DebugHostValues struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"debug_host_values"`
			DebugSeverityValues struct {
				Buckets []struct {
					Key      string `json:"key"`
					DocCount int    `json:"doc_count"`
				} `json:"buckets"`
			} `json:"debug_severity_values"`
		} `json:"aggregations"`
	}

	if err := json.NewDecoder(res.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	// Convert ke map
	result := make(map[string]int)
	for _, bucket := range searchResp.Aggregations.SeverityCounts.Buckets {
		result[bucket.Key] = bucket.DocCount
	}

	return result, nil
}
func parseActivityTime(timeStr string) (time.Time, error) {
	// List of possible time formats
	formats := []string{
		"02/01/06 15:04",            // 25/08/25 08:40
		"2006-01-02 15:04:05",       // 2025-08-25 08:40:00
		"2006-01-02T15:04:05Z",      // ISO format
		"Mon, 02 Jan 2006 15:04",    // Thu, 03 Jul 2025 14:09
		"Mon, 02 Jan 2006 15:04:05", // Thu, 03 Jul 2025 14:09:00
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}
