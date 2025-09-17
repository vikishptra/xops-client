package overview

import (
	"context"
	"fmt"

	"xops-admin/domain"
	domain_overview "xops-admin/domain/user/overview"
	"xops-admin/model"
)

type BugDiscoveryTimelineRepo struct {
	repo       domain.OverviewRepository
	clientRepo domain.ClientRepository
}

func NewBugDiscoveryTimeline(repo domain.OverviewRepository, clientRepo domain.ClientRepository) domain_overview.BugDiscoveryTimelineUseCase {
	return &BugDiscoveryTimelineRepo{
		repo:       repo,
		clientRepo: clientRepo,
	}
}

func (u *BugDiscoveryTimelineRepo) GetDomainByClientID(id string) (*model.DomainClient, error) {
	return u.clientRepo.GetDomainByClientID(id)
}

func (u *BugDiscoveryTimelineRepo) GetRealTimePentesterStatus(ctx context.Context, domainName string) ([]domain_overview.PentesterEffectiveness, error) {
	// Ambil data untuk periode 1 hari terakhir
	pentesters, err := u.repo.GetPentestersEffectiveness(ctx, domainName, 30)
	if err != nil {
		return nil, err
	}

	// Tampilkan semua pentester termasuk yang tidak pernah aktif
	// Bisa diurutkan berdasarkan status aktif atau total findings
	return pentesters, nil
}
func (u *BugDiscoveryTimelineRepo) GetTotalFindingsWithTrend(ctx context.Context, domainName string) (*domain_overview.ResponseTotalFindings, error) {
	return u.repo.GetTotalFindingsWithTrend(ctx, domainName)
}

func (u *BugDiscoveryTimelineRepo) GetLogActivity(ctx context.Context, params domain_overview.LogActivityPaginationParams) (*domain_overview.LogActivityResponse, error) {
	return u.repo.GetLogActivity(context.TODO(), params)
}

// Existing function - Chart 1: Vulnerability Timeline
func (s *BugDiscoveryTimelineRepo) GetVulnerabilityChart(ctx context.Context, period int, domainName, filter string) ([]domain_overview.ChartData, error) {

	stats, err := s.repo.GetVulnerabilityStats(ctx, period, domainName, filter)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("failed to get vulnerability stats: %w", err)
	}
	chartData := ConvertToChartData(stats)

	return chartData, nil
}

// NEW: Chart 2 - Bug Severity Distribution
func (s *BugDiscoveryTimelineRepo) GetBugSeverityDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.SeverityDistribution, error) {
	distributions, err := s.repo.GetBugSeverityDistribution(ctx, domainName, period, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get bug severity distribution: %w", err)
	}
	return distributions, nil
}

// NEW: Chart 2 - Bug Status Distribution
func (s *BugDiscoveryTimelineRepo) GetBugStatusDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.StatusDistribution, error) {
	distributions, err := s.repo.GetBugStatusDistribution(ctx, domainName, period, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get bug status distribution: %w", err)
	}
	return distributions, nil
}

// NEW: Chart 2 - Bug Validation Distribution
func (s *BugDiscoveryTimelineRepo) GetBugValidationDistribution(ctx context.Context, domainName string, period int, status string) ([]domain_overview.ValidationDistribution, error) {
	distributions, err := s.repo.GetBugValidationDistribution(ctx, domainName, period, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get bug validation distribution: %w", err)
	}
	return distributions, nil
}

// NEW: Chart 3 - Host/Domain Bugs Exposure
func (s *BugDiscoveryTimelineRepo) GetHostBugsExposure(ctx context.Context, domainName string, period int) ([]domain_overview.HostExposure, error) {
	exposure, err := s.repo.GetHostBugsExposure(ctx, domainName, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get host bugs exposure: %w", err)
	}
	return exposure, nil
}

func (s *BugDiscoveryTimelineRepo) GetPentestersActivityStats(ctx context.Context, domainName string, period int) ([]domain_overview.PentesterActivity, error) {
	activity, err := s.repo.GetPentestersActivity(ctx, domainName, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get pentesters activity stats: %w", err)
	}
	return activity, nil
}

// NEW: Chart 4 - Bug Type Frequency
func (s *BugDiscoveryTimelineRepo) GetBugTypeFrequency(ctx context.Context, domainName string, period int) ([]domain_overview.BugTypeFrequency, error) {
	frequency, err := s.repo.GetBugTypeFrequency(ctx, domainName, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get bug type frequency: %w", err)
	}
	return frequency, nil
}

// Helper functions
func addAlpha(hex string, alpha int) string {
	if alpha < 0 {
		alpha = 0
	}
	if alpha > 255 {
		alpha = 255
	}
	return fmt.Sprintf("%s%02X", hex, alpha)
}

func ConvertToChartData(stats []domain_overview.VulnStat) []domain_overview.ChartData {
	var charts []domain_overview.ChartData

	for i, stat := range stats {
		color := getFixedColor(i)
		charts = append(charts, domain_overview.ChartData{
			Name:  stat.Name,
			Type:  "line",
			Stack: "Total",
			Label: domain_overview.Label{Show: true, Position: "top"},
			AreaStyle: domain_overview.AreaStyle{
				Color: addAlpha(color, 153), // 153 = 0x99 = transparansi ~60%
			},
			LineStyle: domain_overview.LineStyle{
				Color: color,
				Width: 2,
			},
			Emphasis: domain_overview.Emphasis{Focus: "series"},
			Data:     stat.Data,
		})
	}
	return charts
}

// Updated function to use fixed colors instead of random
func getFixedColor(index int) string {
	colors := []string{
		"#e74c3c", // Red
		"#f39c12", // Orange
		"#3498db", // Blue
		"#2ecc71", // Green
	}

	// Cycle through colors if we have more items than colors
	return colors[index%len(colors)]
}
