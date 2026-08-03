// Package planned registers descriptor-only future mutation operations.
// There are no handlers and no execution path in PR #21.
package planned

import (
	"fmt"
	"sync"

	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

const (
	OpRepairUEFIBCDStore = "boot.repair_uefi_bcd_store"
	operationVersion     = "1.0.0"
	contractBase         = "https://effexorwinpe.local/contracts/recovery"
)

var (
	once     sync.Once
	registry map[string]domain.OperationDescriptor
	errInit  error
)

func catalog() []domain.OperationDescriptor {
	return []domain.OperationDescriptor{
		{
			SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
			OperationID: OpRepairUEFIBCDStore, Version: operationVersion,
			Title: "Repair UEFI BCD store entry", Description: "Future typed repair of UEFI BCD store membership for a selected Windows installation. Not executable in PR #21.",
			Module: "boot", RiskClass: domain.RiskControlledMutation, MutationClass: "config",
			RequiredEvidence: []string{"boot_store_facts", "windows_installation_facts"}, RequiredCapabilities: []string{"mutate_bcd_store"},
			SupportedRuntimes: []string{"winpe"}, RequiresBackup: true,
			RollbackQuality: domain.RollbackBestEffort, RequiresExplicitApproval: true,
			ParametersSchemaRef: contractBase + "/planned/boot.repair_uefi_bcd_store-1.0.0/parameters.schema.json",
			ResultSchemaRef:     contractBase + "/planned/boot.repair_uefi_bcd_store-1.0.0/result.schema.json",
		},
	}
}

func ensure() error {
	once.Do(func() {
		registry = make(map[string]domain.OperationDescriptor, len(catalog()))
		for _, d := range catalog() {
			if err := d.Validate(); err != nil {
				errInit = fmt.Errorf("planned op %s: %w", d.OperationID, err)
				return
			}
			key := d.OperationID + "@" + d.Version
			registry[key] = d
		}
	})
	return errInit
}

// Descriptor returns a planned mutation descriptor when registered.
func Descriptor(operationID, version string) (domain.OperationDescriptor, bool) {
	if err := ensure(); err != nil {
		return domain.OperationDescriptor{}, false
	}
	d, ok := registry[operationID+"@"+version]
	return d, ok
}

// Descriptors returns all planned mutation descriptors.
func Descriptors() []domain.OperationDescriptor {
	if err := ensure(); err != nil {
		return nil
	}
	out := make([]domain.OperationDescriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	return out
}

// MustInit validates the planned catalog at process start in tests.
func MustInit() error { return ensure() }
