// Package assets provides asset discovery and management functionality.
package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Service provides asset management and discovery operations.
type Service struct {
	db       *pgxpool.Pool
	mu       sync.RWMutex
	scanners map[string]AssetScanner
}

// AssetScanner defines the interface for asset discovery scanners.
type AssetScanner interface {
	// Name returns the scanner name
	Name() string
	// Scan performs asset discovery
	Scan(ctx context.Context, target string, config ScanConfig) ([]Asset, error)
}

// ScanConfig holds configuration for asset scanning.
type ScanConfig struct {
	Threads     int
	Timeout     time.Duration
	RateLimit   int
	CustomFlags map[string]string
}

// Asset represents a discovered asset.
type Asset struct {
	ID            uuid.UUID       `json:"id"`
	MissionID     uuid.UUID       `json:"mission_id"`
	ScopeID       *uuid.UUID      `json:"scope_id,omitempty"`
	Type          AssetType       `json:"type"`
	Value         string          `json:"value"`
	Status        AssetStatus     `json:"status"`
	Data          json.RawMessage `json:"data,omitempty"`
	Sources       []string        `json:"sources"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	ScanCount     int             `json:"scan_count"`
	PreviousData  json.RawMessage `json:"previous_data,omitempty"`
	ChangeType    string          `json:"change_type,omitempty"`
	Relationships []Relationship  `json:"relationships,omitempty"`
}

// AssetType represents the type of asset.
type AssetType string

const (
	AssetTypeDomain      AssetType = "domain"
	AssetTypeSubdomain   AssetType = "subdomain"
	AssetTypeIP          AssetType = "ip"
	AssetTypeService     AssetType = "service"
	AssetTypePort        AssetType = "port"
	AssetTypeEndpoint    AssetType = "endpoint"
	AssetTypeTechnology  AssetType = "technology"
	AssetTypeCertificate AssetType = "certificate"
	AssetTypeCloudResource AssetType = "cloud_resource"
)

// AssetStatus represents the status of an asset.
type AssetStatus string

const (
	AssetStatusActive   AssetStatus = "active"
	AssetStatusInactive AssetStatus = "inactive"
	AssetStatusRemoved  AssetStatus = "removed"
)

// Relationship represents a relationship between assets.
type Relationship struct {
	ID               uuid.UUID         `json:"id"`
	SourceAssetID    uuid.UUID         `json:"source_asset_id"`
	TargetAssetID    uuid.UUID         `json:"target_asset_id"`
	RelationshipType RelationshipType  `json:"relationship_type"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// RelationshipType represents the type of relationship between assets.
type RelationshipType string

const (
	RelResolvesTo    RelationshipType = "resolves_to"
	RelHosts         RelationshipType = "hosts"
	RelRuns          RelationshipType = "runs"
	RelServes        RelationshipType = "serves"
	RelDependsOn     RelationshipType = "depends_on"
	RelPartOf        RelationshipType = "part_of"
	RelAssociatedWith RelationshipType = "associated_with"
)

// Scope represents an asset scope definition.
type Scope struct {
	ID          uuid.UUID `json:"id"`
	MissionID   uuid.UUID `json:"mission_id"`
	ScopeType   ScopeType `json:"scope_type"`
	Value       string    `json:"value"`
	Description string    `json:"description"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ScopeType represents the type of scope.
type ScopeType string

const (
	ScopeTypeDomain    ScopeType = "domain"
	ScopeTypeIPRange   ScopeType = "ip_range"
	ScopeTypeCIDR      ScopeType = "cidr"
	ScopeTypeWildcard  ScopeType = "wildcard"
	ScopeTypeURL       ScopeType = "url"
	ScopeTypeMobileApp ScopeType = "mobile_app"
)

// DiscoveryJob represents a discovery job.
type DiscoveryJob struct {
	ID                uuid.UUID   `json:"id"`
	MissionID         uuid.UUID   `json:"mission_id"`
	ScopeID           *uuid.UUID  `json:"scope_id,omitempty"`
	JobType           JobType     `json:"job_type"`
	Status            JobStatus   `json:"status"`
	Config            ScanConfig  `json:"config"`
	TotalTargets      int         `json:"total_targets"`
	ProcessedTargets  int         `json:"processed_targets"`
	FoundAssets       int         `json:"found_assets"`
	StartedAt         *time.Time  `json:"started_at,omitempty"`
	CompletedAt       *time.Time  `json:"completed_at,omitempty"`
	ErrorMessage      string      `json:"error_message,omitempty"`
	CreatedAt         time.Time   `json:"created_at"`
}

// JobType represents the type of discovery job.
type JobType string

const (
	JobTypeSubdomainEnum    JobType = "subdomain_enum"
	JobTypePortScan         JobType = "port_scan"
	JobTypeServiceEnum      JobType = "service_enum"
	JobTypeTechDetect       JobType = "tech_detect"
	JobTypeScreenshot       JobType = "screenshot"
	JobTypeCertificateCheck JobType = "certificate_check"
)

// JobStatus represents the status of a discovery job.
type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusRunning    JobStatus = "running"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
)

// NewService creates a new asset service.
func NewService(db *pgxpool.Pool) *Service {
	return &Service{
		db:       db,
		scanners: make(map[string]AssetScanner),
	}
}

// RegisterScanner registers an asset scanner.
func (s *Service) RegisterScanner(scanner AssetScanner) {
	s.mu.Lock()
	s.scanners[scanner.Name()] = scanner
	s.mu.Unlock()
	slog.Info("registered asset scanner", "name", scanner.Name())
}

// CreateScope creates a new asset scope.
func (s *Service) CreateScope(ctx context.Context, scope *Scope) error {
	scope.ID = uuid.New()
	scope.CreatedAt = time.Now()
	scope.UpdatedAt = time.Now()
	scope.IsActive = true

	// Validate scope
	if err := s.validateScope(scope); err != nil {
		return err
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO asset_scopes (id, mission_id, scope_type, value, description, is_active, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		scope.ID, scope.MissionID, scope.ScopeType, scope.Value,
		scope.Description, scope.IsActive, scope.CreatedAt, scope.UpdatedAt)
	return err
}

// validateScope validates scope input.
func (s *Service) validateScope(scope *Scope) error {
	switch scope.ScopeType {
	case ScopeTypeDomain:
		if !isValidDomain(scope.Value) {
			return fmt.Errorf("invalid domain: %s", scope.Value)
		}
	case ScopeTypeCIDR:
		if _, _, err := net.ParseCIDR(scope.Value); err != nil {
			return fmt.Errorf("invalid CIDR: %s", scope.Value)
		}
	case ScopeTypeIPRange:
		if !isValidIPRange(scope.Value) {
			return fmt.Errorf("invalid IP range: %s", scope.Value)
		}
	case ScopeTypeWildcard:
		if !strings.HasPrefix(scope.Value, "*.") {
			return fmt.Errorf("invalid wildcard domain: %s", scope.Value)
		}
	case ScopeTypeURL:
		if !strings.HasPrefix(scope.Value, "http://") && !strings.HasPrefix(scope.Value, "https://") {
			return fmt.Errorf("invalid URL: %s", scope.Value)
		}
	case ScopeTypeMobileApp:
		// Mobile app bundle ID validation is lenient
	default:
		return fmt.Errorf("unknown scope type: %s", scope.ScopeType)
	}
	return nil
}

// GetScopes retrieves scopes for a mission.
func (s *Service) GetScopes(ctx context.Context, missionID uuid.UUID) ([]*Scope, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, mission_id, scope_type, value, description, is_active, created_at, updated_at
		 FROM asset_scopes WHERE mission_id = $1 ORDER BY created_at DESC`,
		missionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []*Scope
	for rows.Next() {
		var scope Scope
		err := rows.Scan(&scope.ID, &scope.MissionID, &scope.ScopeType, &scope.Value,
			&scope.Description, &scope.IsActive, &scope.CreatedAt, &scope.UpdatedAt)
		if err != nil {
			continue
		}
		scopes = append(scopes, &scope)
	}
	return scopes, nil
}

// CreateDiscoveryJob creates a new discovery job.
func (s *Service) CreateDiscoveryJob(ctx context.Context, job *DiscoveryJob) error {
	job.ID = uuid.New()
	job.Status = JobStatusPending
	job.CreatedAt = time.Now()

	_, err := s.db.Exec(ctx,
		`INSERT INTO discovery_jobs (id, mission_id, scope_id, job_type, status, config, total_targets, processed_targets, found_assets, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		job.ID, job.MissionID, job.ScopeID, job.JobType, job.Status,
		job.Config, job.TotalTargets, job.ProcessedTargets, job.FoundAssets, job.CreatedAt)
	return err
}

// StartDiscoveryJob starts a discovery job.
func (s *Service) StartDiscoveryJob(ctx context.Context, jobID uuid.UUID) error {
	// Update status to running
	now := time.Now()
	_, err := s.db.Exec(ctx,
		`UPDATE discovery_jobs SET status = $1, started_at = $2 WHERE id = $3`,
		JobStatusRunning, now, jobID)
	if err != nil {
		return err
	}

	// Get job details
	job, err := s.getDiscoveryJob(ctx, jobID)
	if err != nil {
		return err
	}

	// Execute job in background
	go s.executeDiscoveryJob(context.Background(), job)

	return nil
}

// getDiscoveryJob retrieves a discovery job by ID.
func (s *Service) getDiscoveryJob(ctx context.Context, jobID uuid.UUID) (*DiscoveryJob, error) {
	// Simplified - in production would scan from database
	return nil, fmt.Errorf("not implemented")
}

// executeDiscoveryJob executes the discovery job.
func (s *Service) executeDiscoveryJob(ctx context.Context, job *DiscoveryJob) {
	slog.Info("starting discovery job",
		"job_id", job.ID,
		"type", job.JobType,
		"mission_id", job.MissionID)

	var err error
	switch job.JobType {
	case JobTypeSubdomainEnum:
		err = s.runSubdomainEnumeration(ctx, job)
	case JobTypePortScan:
		err = s.runPortScan(ctx, job)
	case JobTypeServiceEnum:
		err = s.runServiceEnumeration(ctx, job)
	case JobTypeTechDetect:
		err = s.runTechnologyDetection(ctx, job)
	case JobTypeCertificateCheck:
		err = s.runCertificateCheck(ctx, job)
	default:
		err = fmt.Errorf("unknown job type: %s", job.JobType)
	}

	// Update job status
	status := JobStatusCompleted
	var errorMsg string
	if err != nil {
		status = JobStatusFailed
		errorMsg = err.Error()
		slog.Error("discovery job failed",
			"job_id", job.ID,
			"error", err)
	}

	completedAt := time.Now()
	_, dbErr := s.db.Exec(ctx,
		`UPDATE discovery_jobs SET status = $1, completed_at = $2, error_message = $3, found_assets = $4 WHERE id = $5`,
		status, completedAt, errorMsg, job.FoundAssets, job.ID)
	if dbErr != nil {
		slog.Error("failed to update discovery job", "error", dbErr)
	}

	slog.Info("discovery job completed",
		"job_id", job.ID,
		"status", status,
		"found_assets", job.FoundAssets)
}

// runSubdomainEnumeration performs subdomain enumeration.
func (s *Service) runSubdomainEnumeration(ctx context.Context, job *DiscoveryJob) error {
	// Get scopes for this mission
	scopes, err := s.GetScopes(ctx, job.MissionID)
	if err != nil {
		return err
	}

	var domains []string
	for _, scope := range scopes {
		if scope.ScopeType == ScopeTypeDomain || scope.ScopeType == ScopeTypeWildcard {
			domains = append(domains, scope.Value)
		}
	}

	if len(domains) == 0 {
		return fmt.Errorf("no domains found in scope")
	}

	// Run enumeration (would integrate with actual tools like amass, subfinder)
	for _, domain := range domains {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Simulate discovery
		subdomains := s.discoverSubdomains(ctx, domain)

		for _, subdomain := range subdomains {
			asset := &Asset{
				MissionID: job.MissionID,
				Type:      AssetTypeSubdomain,
				Value:     subdomain,
				Status:    AssetStatusActive,
				Sources:   []string{"subdomain_enum"},
			}

			if err := s.UpsertAsset(ctx, asset); err != nil {
				slog.Error("failed to save subdomain", "error", err)
				continue
			}
			job.FoundAssets++
		}
	}

	return nil
}

// discoverSubdomains simulates subdomain discovery.
func (s *Service) discoverSubdomains(ctx context.Context, domain string) []string {
	// Placeholder - would integrate with actual subdomain enumeration tools
	var subdomains []string
	common := []string{"www", "api", "admin", "dev", "staging", "test", "portal", "app"}
	for _, prefix := range common {
		subdomains = append(subdomains, fmt.Sprintf("%s.%s", prefix, domain))
	}
	return subdomains
}

// runPortScan performs port scanning on discovered assets.
func (s *Service) runPortScan(ctx context.Context, job *DiscoveryJob) error {
	// Get IP assets
	assets, err := s.GetAssetsByType(ctx, job.MissionID, AssetTypeIP)
	if err != nil {
		return err
	}

	if len(assets) == 0 {
		// Try to resolve domains to IPs
		domains, err := s.GetAssetsByType(ctx, job.MissionID, AssetTypeDomain)
		if err != nil {
			return err
		}

		for _, domain := range domains {
			ips := s.resolveDomain(ctx, domain.Value)
			for _, ip := range ips {
				asset := &Asset{
					MissionID: job.MissionID,
					Type:      AssetTypeIP,
					Value:     ip,
					Status:    AssetStatusActive,
					Sources:   []string{"dns_resolution"},
				}
				if err := s.UpsertAsset(ctx, asset); err != nil {
					slog.Error("failed to save IP", "error", err)
					continue
				}
				assets = append(assets, asset)
			}
		}
	}

	// Scan ports
	for _, asset := range assets {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		openPorts := s.scanPorts(ctx, asset.Value)
		for _, port := range openPorts {
			serviceAsset := &Asset{
				MissionID: job.MissionID,
				Type:      AssetTypeService,
				Value:     fmt.Sprintf("%s:%d", asset.Value, port),
				Status:    AssetStatusActive,
				Sources:   []string{"port_scan"},
				Data:      json.RawMessage(fmt.Sprintf(`{"port":%d,"protocol":"tcp"}`, port)),
			}

			if err := s.UpsertAsset(ctx, serviceAsset); err != nil {
				slog.Error("failed to save service", "error", err)
				continue
			}
			job.FoundAssets++
		}
	}

	return nil
}

// scanPorts simulates port scanning.
func (s *Service) scanPorts(ctx context.Context, ip string) []int {
	// Placeholder - would integrate with actual port scanners like nmap, masscan
	commonPorts := []int{80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443}
	var open []int
	for _, port := range commonPorts {
		if ctx.Err() != nil {
			break
		}
		// Simulate some open ports
		if port == 80 || port == 443 || port == 22 {
			open = append(open, port)
		}
	}
	return open
}

// runServiceEnumeration enumerates services on open ports.
func (s *Service) runServiceEnumeration(ctx context.Context, job *DiscoveryJob) error {
	// Get service assets
	services, err := s.GetAssetsByType(ctx, job.MissionID, AssetTypeService)
	if err != nil {
		return err
	}

	for _, service := range services {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Identify service
		info := s.identifyService(ctx, service.Value)
		if info.Name != "" {
			// Update service data
			data, _ := json.Marshal(info)
			service.Data = data
			if err := s.UpdateAsset(ctx, service); err != nil {
				slog.Error("failed to update service", "error", err)
			}
		}
	}

	return nil
}

// ServiceInfo holds service enumeration data.
type ServiceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Banner      string `json:"banner"`
	CPE         string `json:"cpe,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
}

// identifyService simulates service identification.
func (s *Service) identifyService(ctx context.Context, endpoint string) ServiceInfo {
	// Placeholder - would integrate with actual service fingerprinting
	return ServiceInfo{
		Name:    "unknown",
		Version: "",
	}
}

// runTechnologyDetection detects technologies used by web services.
func (s *Service) runTechnologyDetection(ctx context.Context, job *DiscoveryJob) error {
	// Get service assets
	services, err := s.GetAssetsByType(ctx, job.MissionID, AssetTypeService)
	if err != nil {
		return err
	}

	for _, service := range services {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Detect technologies
		techs := s.detectTechnologies(ctx, service.Value)
		for _, tech := range techs {
			techAsset := &Asset{
				MissionID: job.MissionID,
				Type:      AssetTypeTechnology,
				Value:     tech.Name,
				Status:    AssetStatusActive,
				Sources:   []string{"technology_detection"},
				Data:      json.RawMessage(fmt.Sprintf(`{"version":"%s","confidence":%d}`, tech.Version, tech.Confidence)),
			}

			if err := s.UpsertAsset(ctx, techAsset); err != nil {
				slog.Error("failed to save technology", "error", err)
				continue
			}
			job.FoundAssets++
		}
	}

	return nil
}

// TechnologyInfo holds technology detection data.
type TechnologyInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Confidence int    `json:"confidence"`
}

// detectTechnologies simulates technology detection.
func (s *Service) detectTechnologies(ctx context.Context, endpoint string) []TechnologyInfo {
	// Placeholder - would integrate with tools like Wappalyzer
	return []TechnologyInfo{}
}

// runCertificateCheck checks SSL/TLS certificates.
func (s *Service) runCertificateCheck(ctx context.Context, job *DiscoveryJob) error {
	// Get service assets on 443
	services, err := s.GetAssetsByType(ctx, job.MissionID, AssetTypeService)
	if err != nil {
		return err
	}

	for _, service := range services {
		// Check if it's an HTTPS service
		if strings.HasSuffix(service.Value, ":443") || strings.Contains(string(service.Data), "tls") {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			cert := s.checkCertificate(ctx, service.Value)
			if cert != nil {
				certAsset := &Asset{
					MissionID: job.MissionID,
					Type:      AssetTypeCertificate,
					Value:     cert.SubjectCN,
					Status:    AssetStatusActive,
					Sources:   []string{"certificate_check"},
				}

				if err := s.UpsertAsset(ctx, certAsset); err != nil {
					slog.Error("failed to save certificate", "error", err)
					continue
				}
				job.FoundAssets++
			}
		}
	}

	return nil
}

// CertificateInfo holds certificate data.
type CertificateInfo struct {
	SubjectCN        string    `json:"subject_cn"`
	SubjectOrg       string    `json:"subject_org"`
	IssuerCN         string    `json:"issuer_cn"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	SANs             []string  `json:"sans"`
}

// checkCertificate simulates certificate checking.
func (s *Service) checkCertificate(ctx context.Context, endpoint string) *CertificateInfo {
	// Placeholder - would actually connect and retrieve certificate
	return nil
}

// UpsertAsset creates or updates an asset.
func (s *Service) UpsertAsset(ctx context.Context, asset *Asset) error {
	// Check if asset exists
	existing, err := s.getAssetByValue(ctx, asset.MissionID, asset.Type, asset.Value)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if existing != nil {
		// Update existing asset
		asset.ID = existing.ID
		asset.FirstSeen = existing.FirstSeen
		asset.LastSeen = time.Now()
		asset.ScanCount = existing.ScanCount + 1

		// Check for changes
		if string(asset.Data) != string(existing.Data) {
			asset.PreviousData = existing.Data
			asset.ChangeType = "modified"

			// Log change
			s.logAssetChange(ctx, asset, existing.Data, asset.Data)
		} else {
			asset.ChangeType = "unchanged"
		}

		return s.UpdateAsset(ctx, asset)
	}

	// Create new asset
	asset.ID = uuid.New()
	asset.FirstSeen = time.Now()
	asset.LastSeen = time.Now()
	asset.ScanCount = 1
	asset.ChangeType = "new"

	_, err = s.db.Exec(ctx,
		`INSERT INTO assets (id, mission_id, scope_id, asset_type, value, status, data, sources, first_seen, last_seen, scan_count, change_type)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		asset.ID, asset.MissionID, asset.ScopeID, asset.Type, asset.Value,
		asset.Status, asset.Data, asset.Sources, asset.FirstSeen, asset.LastSeen,
		asset.ScanCount, asset.ChangeType)

	// Log change for new asset
	if err == nil {
		s.logAssetChange(ctx, asset, nil, asset.Data)
	}

	return err
}

// UpdateAsset updates an existing asset.
func (s *Service) UpdateAsset(ctx context.Context, asset *Asset) error {
	_, err := s.db.Exec(ctx,
		`UPDATE assets SET status = $1, data = $2, sources = $3, last_seen = $4,
		 scan_count = $5, previous_data = $6, change_type = $7, updated_at = $8
		 WHERE id = $9`,
		asset.Status, asset.Data, asset.Sources, asset.LastSeen,
		asset.ScanCount, asset.PreviousData, asset.ChangeType, time.Now(), asset.ID)
	return err
}

// getAssetByValue retrieves an asset by mission, type, and value.
func (s *Service) getAssetByValue(ctx context.Context, missionID uuid.UUID, assetType AssetType, value string) (*Asset, error) {
	var asset Asset
	err := s.db.QueryRow(ctx,
		`SELECT id, mission_id, scope_id, asset_type, value, status, data, sources,
		 first_seen, last_seen, scan_count, previous_data, change_type
		 FROM assets WHERE mission_id = $1 AND asset_type = $2 AND value = $3`,
		missionID, assetType, value).Scan(
		&asset.ID, &asset.MissionID, &asset.ScopeID, &asset.Type, &asset.Value,
		&asset.Status, &asset.Data, &asset.Sources, &asset.FirstSeen, &asset.LastSeen,
		&asset.ScanCount, &asset.PreviousData, &asset.ChangeType)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

// GetAssetsByType retrieves assets by type.
func (s *Service) GetAssetsByType(ctx context.Context, missionID uuid.UUID, assetType AssetType) ([]*Asset, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, mission_id, scope_id, asset_type, value, status, data, sources,
		 first_seen, last_seen, scan_count, change_type
		 FROM assets WHERE mission_id = $1 AND asset_type = $2 AND status = 'active'`,
		missionID, assetType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*Asset
	for rows.Next() {
		var asset Asset
		err := rows.Scan(&asset.ID, &asset.MissionID, &asset.ScopeID, &asset.Type, &asset.Value,
			&asset.Status, &asset.Data, &asset.Sources, &asset.FirstSeen, &asset.LastSeen,
			&asset.ScanCount, &asset.ChangeType)
		if err != nil {
			continue
		}
		assets = append(assets, &asset)
	}
	return assets, nil
}

// logAssetChange logs an asset change.
func (s *Service) logAssetChange(ctx context.Context, asset *Asset, oldVal, newVal json.RawMessage) {
	changeType := asset.ChangeType
	if changeType == "" {
		changeType = "modified"
	}

	_, err := s.db.Exec(ctx,
		`INSERT INTO asset_changes (mission_id, asset_id, change_type, field_name, old_value, new_value)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		asset.MissionID, asset.ID, changeType, "data", oldVal, newVal)
	if err != nil {
		slog.Error("failed to log asset change", "error", err)
	}
}

// resolveDomain resolves a domain to IPs.
func (s *Service) resolveDomain(ctx context.Context, domain string) []string {
	var ips []string
	timeout := 5 * time.Second

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Use Go's net.Resolver
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return ips
	}

	for _, addr := range addrs {
		// Only include IPv4 addresses for simplicity
		if net.ParseIP(addr).To4() != nil {
			ips = append(ips, addr)
		}
	}
	return ips
}

// isValidDomain checks if a string is a valid domain.
func isValidDomain(domain string) bool {
	// Simple validation - could use more comprehensive regex
	if len(domain) > 253 {
		return false
	}
	pattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$`)
	return pattern.MatchString(domain)
}

// isValidIPRange checks if a string is a valid IP range.
func isValidIPRange(rangeStr string) bool {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return false
	}
	ip1 := net.ParseIP(strings.TrimSpace(parts[0]))
	ip2 := net.ParseIP(strings.TrimSpace(parts[1]))
	return ip1 != nil && ip2 != nil
}
