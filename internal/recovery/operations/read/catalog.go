package read

import (
	"github.com/effexorxruser/EffexorWinPE/internal/recovery/domain"
)

const (
	collectorName    = "effexor-recovery-read-operation"
	collectorVersion = "1.0.0"

	contractBase     = "https://effexorwinpe.local/contracts/recovery"
	paramsSchemaRef  = contractBase + "/read-operation-request-1.0.0/read-operation-request.schema.json"
	resultSchemaRef  = contractBase + "/read-operation-result-1.0.0/read-operation-result.schema.json"
	operationVersion = "1.0.0"
)

type catalogEntry struct {
	descriptor  domain.OperationDescriptor
	targetTypes []string
}

func catalogEntries() []catalogEntry {
	return []catalogEntry{
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "windows.inspect_installation", Version: operationVersion,
				Title: "Inspect Windows installation", Description: "Read-only inspection of a discovered Windows installation from Case evidence.",
				Module: "windows", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"windows_installation_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"windows_installation"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "boot.inspect_firmware_mode", Version: operationVersion,
				Title: "Inspect firmware mode", Description: "Read-only inspection of boot firmware mode from Case evidence.",
				Module: "boot", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"firmware_environment_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"firmware"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "boot.inspect_bcd_store", Version: operationVersion,
				Title: "Inspect BCD store", Description: "Read-only inspection of a discovered boot configuration store from Case evidence.",
				Module: "boot", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"boot_store_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"boot_store"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "boot.inspect_efi_layout", Version: operationVersion,
				Title: "Inspect EFI layout", Description: "Read-only inspection of EFI system partition layout from Case evidence.",
				Module: "boot", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"partition_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"firmware", "disk"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "storage.inspect_disk_health", Version: operationVersion,
				Title: "Inspect disk health", Description: "Read-only inspection of disk health signals from Case evidence.",
				Module: "storage", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"disk_health_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"disk"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "storage.inspect_partition_layout", Version: operationVersion,
				Title: "Inspect partition layout", Description: "Read-only inspection of partition layout from Case evidence.",
				Module: "storage", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"partition_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"disk", "firmware"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "bitlocker.inspect_inventory", Version: operationVersion,
				Title: "Inspect BitLocker inventory", Description: "Read-only inspection of BitLocker volume inventory from Case evidence.",
				Module: "bitlocker", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{"bitlocker_volume_facts"}, RequiredCapabilities: []string{"read_case_snapshot"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"firmware", "volume"},
		},
		{
			descriptor: domain.OperationDescriptor{
				SchemaName: domain.SchemaOperationDescriptor, SchemaVersion: domain.SchemaVersion,
				OperationID: "case.verify_store_integrity", Version: operationVersion,
				Title: "Verify Case Store integrity", Description: "Read-only integrity verification of the persisted Case Store.",
				Module: "case", RiskClass: domain.RiskReadOnly, MutationClass: "none",
				RequiredEvidence: []string{}, RequiredCapabilities: []string{"read_case_store"},
				SupportedRuntimes: []string{"winpe", "windows"}, RequiresBackup: false,
				RollbackQuality: domain.RollbackUnavailable, RequiresExplicitApproval: false,
				ParametersSchemaRef: paramsSchemaRef, ResultSchemaRef: resultSchemaRef,
			},
			targetTypes: []string{"firmware"},
		},
	}
}
