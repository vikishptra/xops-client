package postgres

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"xops-admin/domain"
	util_uuid "xops-admin/util/uuid"
)

type ListBugRepo struct {
	db *gorm.DB
}

func NewListBugRepository(db *gorm.DB) domain.ListBugRepository {
	return &ListBugRepo{
		db: db,
	}
}

func (r *ListBugRepo) GetBugs(ctx context.Context, filter domain.ListBugFilter) (*domain.ListBugResponse, error) {
	var bugs []domain.ListBug

	// Set default limit
	if filter.Limit == 0 {
		filter.Limit = 10
	}

	// Set default sort
	if filter.SortBy == "" {
		filter.SortBy = "created_at"
	}
	if filter.SortOrder == "" {
		filter.SortOrder = "desc"
	}

	// Set default direction
	if filter.Direction == "" {
		filter.Direction = "next"
	}

	// Build base query with JOIN
	query := r.db.WithContext(ctx).
		Select(`
			list_bugs.id,
			list_bugs.host,
			list_bugs.method,
			list_bugs.status_code,
			list_bugs.tool,
			list_bugs.url,
			list_bugs.pentester_ip,
			list_bugs.severity,
			list_bugs.status,
			list_bugs.vulnerability,
			list_bugs.validation,
			list_bugs.flag_domain,
			list_bugs.created_at,
			list_bugs.updated_at,
			list_vulnerabilities.name_bug as name_bug,
			list_vulnerabilities.type_bug as type_bug,
			list_vulnerabilities.description_bug as description_bug
		`).
		Table("list_bugs").
		Joins("LEFT JOIN list_vulnerabilities ON list_bugs.id_list_vulnerability = list_vulnerabilities.unique_id")

	// Apply search filter with parameterized queries to prevent SQL injection
	if filter.Search != "" {
		searchTerm := "%" + strings.ToLower(filter.Search) + "%"
		query = query.Where(`
			UPPER(list_bugs.status) LIKE UPPER(?) OR 
			LOWER(list_bugs.host) LIKE ? OR 
			UPPER(list_bugs.severity) LIKE UPPER(?) OR 
			LOWER(list_bugs.url) LIKE ? OR 
			list_bugs.vulnerability = ? OR
			LOWER(list_vulnerabilities.name_bug) LIKE ? OR
			LOWER(list_vulnerabilities.type_bug) LIKE ?`,
			searchTerm, searchTerm, searchTerm, searchTerm, filter.Search, searchTerm, searchTerm,
		)
	}

	// Apply flag_domain filter
	if filter.FlagDomain != "" {
		query = query.Where("list_bugs.flag_domain = ?", filter.FlagDomain)
	}

	// Apply filters
	if filter.Severity != "" {
		query = query.Where("list_bugs.severity = ?", strings.ToUpper(filter.Severity))
	}
	if filter.Status != "" {
		query = query.Where("list_bugs.status = ?", strings.ToUpper(filter.Status))
	}

	// Handle CSV export - get all records without pagination
	if filter.Convert == "csv" {
		// For CSV, ignore pagination and get all matching records
		var orderClause string
		sortColumn := filter.SortBy

		// Handle sorting with table prefix for ambiguous columns
		if sortColumn == "created_at" || sortColumn == "id" || sortColumn == "severity" || sortColumn == "status" {
			sortColumn = "list_bugs." + sortColumn
		}

		// Apply sorting
		if filter.SortBy == "id" {
			orderClause = fmt.Sprintf("list_bugs.id %s", strings.ToUpper(filter.SortOrder))
		} else {
			orderClause = fmt.Sprintf("%s %s, list_bugs.id %s",
				sortColumn, strings.ToUpper(filter.SortOrder), strings.ToUpper(filter.SortOrder))
		}
		query = query.Order(orderClause)

		// Execute query to get all records
		if err := query.Scan(&bugs).Error; err != nil {
			return nil, fmt.Errorf("failed to fetch bugs for CSV: %w", err)
		}

		// Convert to CSV and return
		csvData, err := r.convertToCSV(bugs)
		if err != nil {
			return nil, fmt.Errorf("failed to convert to CSV: %w", err)
		}

		// Return CSV data in response
		response := &domain.ListBugResponse{
			Success: true,
			Message: "CSV data generated successfully",
			Data:    nil, // No need to return data array for CSV
			CSVData: csvData,
			Pagination: domain.PaginationInfo{
				Size:        len(bugs),
				HasNext:     false,
				HasPrevious: false,
			},
		}

		return response, nil
	}

	// Regular pagination logic continues here...
	// Apply cursor-based pagination
	if filter.LastID != 0 {
		if filter.Direction == "previous" {
			// For previous pagination: we need to go back to where we came from
			// The key insight: we should use the FIRST item of current page as reference
			// Not the last_id from the previous request
			// For DESC order: go back means getting records with higher IDs
			// But we need to limit this to avoid skipping too far
			if filter.SortOrder == "desc" {
				query = query.Where("list_bugs.id > ?", filter.LastID)
			} else {
				query = query.Where("list_bugs.id < ?", filter.LastID)
			}
		} else {
			// Next pagination: continue forward from last_id
			if filter.SortOrder == "desc" {
				query = query.Where("list_bugs.id < ?", filter.LastID)
			} else {
				query = query.Where("list_bugs.id > ?", filter.LastID)
			}
		}
	}

	// Apply sorting
	var orderClause string
	sortColumn := filter.SortBy

	// Handle sorting with table prefix for ambiguous columns
	if sortColumn == "created_at" || sortColumn == "id" || sortColumn == "severity" || sortColumn == "status" {
		sortColumn = "list_bugs." + sortColumn
	}

	// Apply sorting
	if filter.Direction == "previous" {
		// For previous: we want to get records in ascending order of ID
		// so we get the "closest" record first (ID 4), not the furthest (ID 5)
		// Then we'll reverse the results to maintain display consistency
		if filter.SortBy == "id" {
			orderClause = "list_bugs.id ASC"
		} else {
			// For other fields, still sort by field but use ASC for ID tiebreaker
			orderClause = fmt.Sprintf("%s %s, list_bugs.id ASC",
				sortColumn, strings.ToUpper(filter.SortOrder))
		}
	} else {
		// For next: use normal order
		if filter.SortBy == "id" {
			orderClause = fmt.Sprintf("list_bugs.id %s", strings.ToUpper(filter.SortOrder))
		} else {
			orderClause = fmt.Sprintf("%s %s, list_bugs.id %s",
				sortColumn, strings.ToUpper(filter.SortOrder), strings.ToUpper(filter.SortOrder))
		}
	}
	query = query.Order(orderClause)

	// Limit results (fetch one extra to check if there's more)
	query = query.Limit(filter.Limit + 1)

	// Execute query
	if err := query.Scan(&bugs).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %w", err)
	}

	// FIXED: Reverse results for previous pagination to maintain consistent display order
	if filter.Direction == "previous" {
		for i, j := 0, len(bugs)-1; i < j; i, j = i+1, j-1 {
			bugs[i], bugs[j] = bugs[j], bugs[i]
		}
	}

	// Check if there are more results
	hasMore := len(bugs) > filter.Limit
	if hasMore {
		bugs = bugs[:filter.Limit] // Remove the extra item
	}

	// FIXED: Simplified hasNext/hasPrev logic
	var hasNext, hasPrev bool

	if len(bugs) > 0 {
		firstBugID := bugs[0].Id
		lastBugID := bugs[len(bugs)-1].Id

		if filter.Direction == "next" {
			hasNext = hasMore

			// Check if there are previous records
			if filter.LastID != 0 {
				hasPrev = true // If we used LastID, there must be previous data
			} else {
				// For first page, check if there are records before first item
				hasPrev = r.checkHasPrevious(ctx, filter, firstBugID)
			}
		} else {
			// Direction is "previous"
			hasPrev = hasMore

			// Check if there are next records
			hasNext = r.checkHasNext(ctx, filter, lastBugID)
		}
	}

	// Convert to response bugs
	var responseBugs []domain.ListBug
	for _, bug := range bugs {
		responseBug := domain.ListBug{
			Id:             bug.Id,
			NameBug:        bug.NameBug,
			TypeBug:        bug.TypeBug,
			DescriptionBug: bug.DescriptionBug,
			Host:           bug.Host,
			Method:         bug.Method,
			StatusCode:     bug.StatusCode,
			Tool:           bug.Tool,
			URL:            bug.URL,
			PentesterIP:    bug.PentesterIP,
			Severity:       util_uuid.Capitalize(bug.Severity),
			Status:         util_uuid.Capitalize(bug.Status),
			Vulnerability:  util_uuid.Capitalize(bug.Vulnerability),
			Validation:     util_uuid.Capitalize(bug.Validation),
			FlagDomain:     bug.FlagDomain,
			CreatedAt:      bug.CreatedAt,
			UpdatedAt:      bug.UpdatedAt,
		}
		responseBugs = append(responseBugs, responseBug)
	}

	// Prepare response
	response := &domain.ListBugResponse{
		Success: true,
		Message: "Data retrieved successfully",
		Data:    responseBugs,
		Pagination: domain.PaginationInfo{
			Size:        len(responseBugs),
			HasNext:     hasNext,
			HasPrevious: hasPrev,
		},
	}

	return response, nil
}

// convertToCSV converts bug data to CSV format
func (r *ListBugRepo) convertToCSV(bugs []domain.ListBug) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write CSV headers matching the table columns in the image
	headers := []string{
		"No",
		"Date Created",
		"Bug Name",
		"Bug Type",
		"Description",
		"Url",
		"Severity",
		"Status",
	}

	if err := writer.Write(headers); err != nil {
		return "", fmt.Errorf("failed to write CSV headers: %w", err)
	}

	// Write data rows
	for i, bug := range bugs {
		// Format date to match the format in the image (DD/MM/YY HH:MM)
		dateCreated := bug.CreatedAt.Format("02/01/06 15:04")

		record := []string{
			strconv.Itoa(i + 1), // No (sequential number)
			dateCreated,         // Date Created
			bug.NameBug,         // Bug Name
			bug.TypeBug,
			bug.DescriptionBug,                 // Description
			bug.URL,                            // Host/Domain
			util_uuid.Capitalize(bug.Severity), // Severity
			util_uuid.Capitalize(bug.Status),   // Status
		}

		if err := writer.Write(record); err != nil {
			return "", fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.String(), nil
}

// FIXED: Helper function to check if there are previous records
func (r *ListBugRepo) checkHasPrevious(ctx context.Context, filter domain.ListBugFilter, firstBugID int64) bool {
	var count int64
	query := r.db.WithContext(ctx).
		Table("list_bugs").
		Joins("LEFT JOIN list_vulnerabilities ON list_bugs.id_list_vulnerability = list_vulnerabilities.unique_id")

	// Apply same filters
	r.applyFilters(query, filter)

	// Check for records before first item based on sort order
	if filter.SortOrder == "desc" {
		query = query.Where("list_bugs.id > ?", firstBugID)
	} else {
		query = query.Where("list_bugs.id < ?", firstBugID)
	}

	query.Count(&count)
	return count > 0
}

// FIXED: Helper function to check if there are next records
func (r *ListBugRepo) checkHasNext(ctx context.Context, filter domain.ListBugFilter, lastBugID int64) bool {
	var count int64
	query := r.db.WithContext(ctx).
		Table("list_bugs").
		Joins("LEFT JOIN list_vulnerabilities ON list_bugs.id_list_vulnerability = list_vulnerabilities.unique_id")

	// Apply same filters
	r.applyFilters(query, filter)

	// Check for records after last item based on sort order
	if filter.SortOrder == "desc" {
		query = query.Where("list_bugs.id < ?", lastBugID)
	} else {
		query = query.Where("list_bugs.id > ?", lastBugID)
	}

	query.Count(&count)
	return count > 0
}

// FIXED: Helper function to apply common filters
func (r *ListBugRepo) applyFilters(query *gorm.DB, filter domain.ListBugFilter) {
	if filter.Search != "" {
		searchTerm := "%" + strings.ToLower(filter.Search) + "%"
		query.Where(`
			UPPER(list_bugs.status) LIKE UPPER(?) OR 
			LOWER(list_bugs.host) LIKE ? OR 
			UPPER(list_bugs.severity) LIKE UPPER(?) OR 
			LOWER(list_bugs.url) LIKE ? OR 
			list_bugs.vulnerability = ? OR
			LOWER(list_vulnerabilities.name_bug) LIKE ? OR
			LOWER(list_vulnerabilities.type_bug) LIKE ?`,
			searchTerm, searchTerm, searchTerm, searchTerm, filter.Search, searchTerm, searchTerm,
		)
	}

	if filter.FlagDomain != "" {
		query.Where("list_bugs.flag_domain = ?", filter.FlagDomain)
	}

	if filter.Severity != "" {
		query.Where("list_bugs.severity = ?", filter.Severity)
	}

	if filter.Status != "" {
		query.Where("list_bugs.status = ?", filter.Status)
	}
}
