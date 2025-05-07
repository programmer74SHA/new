package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/domain"
	scannerPort "gitlab.apk-group.net/siem/backend/asset-discovery/internal/scanner/port"
)

var (
	ErrScannerOnCreate     = errors.New("error on creating new scanner")
	ErrScannerOnUpdate     = errors.New("error on updating scanner")
	ErrScannerOnDelete     = errors.New("error on deleting scanner")
	ErrScannerNotFound     = errors.New("scanner not found")
	ErrInvalidScannerInput = errors.New("invalid scanner input")
)

type scannerService struct {
	repo scannerPort.Repo
}

func NewScannerService(repo scannerPort.Repo) scannerPort.Service {
	return &scannerService{
		repo: repo,
	}
}

func (s *scannerService) CreateScanner(ctx context.Context, scanner domain.ScannerDomain) (int64, error) {
	log.Printf("Service: Creating scanner: %+v", scanner)

	if scanner.Name == "" || scanner.ScanType == "" {
		log.Printf("Service: Invalid scanner input - missing name or type")
		return 0, ErrInvalidScannerInput
	}

	// Validate scanner based on type
	if err := s.validateScanner(scanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		return 0, ErrInvalidScannerInput
	}

	// Set timestamps
	scanner.CreatedAt = time.Now()
	scanner.UpdatedAt = time.Now()

	// Create scanner in repository
	scannerID, err := s.repo.Create(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error creating scanner: %v", err)
		return 0, ErrScannerOnCreate
	}

	log.Printf("Service: Successfully created scanner with ID: %d", scannerID)
	return scannerID, nil
}

// validateScanner ensures scanner has all required fields based on type
func (s *scannerService) validateScanner(scanner domain.ScannerDomain) error {
	switch scanner.ScanType {
	case domain.ScannerTypeNmap:
		if scanner.Target == "" || scanner.Type == "" {
			return fmt.Errorf("NMAP scanner requires target and type")
		}

		switch scanner.Target {
		case "IP":
			if scanner.IP == "" {
				return fmt.Errorf("NMAP IP scan requires an IP address")
			}
		case "Network":
			if scanner.IP == "" || scanner.Subnet == 0 {
				return fmt.Errorf("NMAP Network scan requires IP and subnet")
			}
		case "Range":
			if scanner.StartIP == "" || scanner.EndIP == "" {
				return fmt.Errorf("NMAP Range scan requires start and end IPs")
			}
		default:
			return fmt.Errorf("invalid NMAP target type: %s", scanner.Target)
		}

	case domain.ScannerTypeVCenter:
		if scanner.IP == "" || scanner.Port == "" || scanner.Username == "" || scanner.Password == "" {
			return fmt.Errorf("VCenter scanner requires IP, port, username, and password")
		}

	case domain.ScannerTypeDomain:
		if scanner.IP == "" || scanner.Port == "" || scanner.Username == "" ||
			scanner.Password == "" || scanner.Domain == "" || scanner.AuthenticationType == "" {
			return fmt.Errorf("Domain scanner requires IP, port, username, password, domain, and authentication type")
		}
	default:
		return fmt.Errorf("invalid scanner type: %s", scanner.ScanType)
	}

	// Validate schedule if provided
	if scanner.Schedule != nil {
		schedule := scanner.Schedule
		if schedule.FrequencyValue <= 0 || schedule.FrequencyUnit == "" {
			return fmt.Errorf("schedule requires frequency value and unit")
		}
	}

	return nil
}

func (s *scannerService) GetScannerByID(ctx context.Context, scannerID int64) (*domain.ScannerDomain, error) {
	log.Printf("Service: Getting scanner with ID: %d", scannerID)

	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error from repository: %v", err)
		return nil, err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return nil, ErrScannerNotFound
	}

	log.Printf("Service: Successfully retrieved scanner: %+v", scanner)
	return scanner, nil
}

func (s *scannerService) UpdateScanner(ctx context.Context, scanner domain.ScannerDomain) error {
	log.Printf("Service: Updating scanner: %+v", scanner)

	if scanner.ID == 0 {
		log.Printf("Service: Invalid scanner input - missing ID")
		return ErrInvalidScannerInput
	}

	// Validate scanner based on type
	if err := s.validateScanner(scanner); err != nil {
		log.Printf("Service: Scanner validation failed: %v", err)
		return ErrInvalidScannerInput
	}

	// Check if scanner exists
	existing, err := s.GetScannerByID(ctx, scanner.ID)
	if err != nil {
		log.Printf("Service: Scanner existence check failed: %v", err)
		return err
	}

	log.Printf("Service: Found existing scanner: %+v", existing)

	// Update timestamps
	scanner.UpdatedAt = time.Now()
	if existing.CreatedAt.IsZero() {
		scanner.CreatedAt = time.Now()
	} else {
		scanner.CreatedAt = existing.CreatedAt
	}

	// Update scanner in repository
	err = s.repo.Update(ctx, scanner)
	if err != nil {
		log.Printf("Service: Error updating scanner: %v", err)
		return ErrScannerOnUpdate
	}

	log.Printf("Service: Successfully updated scanner")
	return nil
}

func (s *scannerService) DeleteScanner(ctx context.Context, scannerID int64) error {
	log.Printf("Service: Deleting scanner with ID: %d", scannerID)

	// Check if scanner exists
	scanner, err := s.repo.GetByID(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error checking scanner existence: %v", err)
		return err
	}

	if scanner == nil {
		log.Printf("Service: Scanner not found for ID: %d", scannerID)
		return ErrScannerNotFound
	}

	// Delete scanner in repository
	err = s.repo.Delete(ctx, scannerID)
	if err != nil {
		log.Printf("Service: Error deleting scanner: %v", err)
		return ErrScannerOnDelete
	}

	log.Printf("Service: Successfully deleted scanner")
	return nil
}

func (s *scannerService) DeleteScanners(ctx context.Context, scannerIDs []int64) (int, error) {
	log.Printf("Service: Batch deleting %d scanners", len(scannerIDs))

	if len(scannerIDs) == 0 {
		return 0, nil
	}

	// Delete scanners in batch
	count, err := s.repo.DeleteBatch(ctx, scannerIDs)
	if err != nil {
		log.Printf("Service: Error batch deleting scanners: %v", err)
		return 0, err
	}

	log.Printf("Service: Successfully deleted %d scanners", count)
	return count, nil
}

func (s *scannerService) ListScanners(ctx context.Context, filter domain.ScannerFilter, pagination domain.Pagination) ([]domain.ScannerDomain, int, error) {
	log.Printf("Service: Listing scanners with filter: %+v, pagination: %+v", filter, pagination)

	// Get scanners from repository with filtering, sorting, and pagination
	scanners, totalCount, err := s.repo.List(ctx, filter, pagination)
	if err != nil {
		log.Printf("Service: Error listing scanners: %v", err)
		return nil, 0, err
	}

	log.Printf("Service: Successfully listed %d scanners (total: %d)", len(scanners), totalCount)
	return scanners, totalCount, nil
}

func (s *scannerService) BatchUpdateScannersEnabled(ctx context.Context, ids []int64, Status bool) (int, error) {
	log.Printf("Service: Batch updating %d scanners to status=%v", len(ids), Status)

	if len(ids) == 0 {
		log.Printf("Service: Empty scanner ID list provided")
		return 0, nil
	}

	// Update scanners in repository
	count, err := s.repo.BatchUpdateEnabled(ctx, ids, Status)
	if err != nil {
		log.Printf("Service: Error batch updating scanners: %v", err)
		return 0, err
	}

	log.Printf("Service: Successfully batch updated %d scanners", count)
	return count, nil
}
