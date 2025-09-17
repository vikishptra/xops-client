package domain

import (
	"context"

	domain_overview "xops-admin/domain/user/overview"
)

type BulkUpdateSecurityChecklistRepository interface {
	UpdateSecurityChecklistItems(ctx context.Context, updates []domain_overview.SecurityChecklistBulkUpdate) error
}
