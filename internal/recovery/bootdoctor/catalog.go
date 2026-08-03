package bootdoctor

// Finding codes emitted by Boot Doctor. These are analysis labels only; they
// never authorize mutation or repair execution.
const (
	CodeFirmwareModeUnknown               = "firmware_mode_unknown"
	CodeFirmwareModeConflicting           = "firmware_mode_conflicting"
	CodeUEFIWithMBRSystemDisk             = "uefi_with_mbr_system_disk"
	CodeLegacyWithGPTLayout               = "legacy_with_gpt_layout"
	CodeUnsupportedLegacyBootTopology     = "unsupported_legacy_boot_topology"
	CodeWindowsInstallationMissing        = "windows_installation_missing"
	CodeMultipleWindowsInstallations      = "multiple_windows_installations"
	CodeWindowsInstallationAmbiguous      = "windows_installation_ambiguous"
	CodeWindowsPartitionRelationUnknown   = "windows_partition_relation_unknown"
	CodeWindowsSystemDiskRelationUnknown  = "windows_system_disk_relation_unknown"
	CodeWindowsInstallationIncomplete     = "windows_installation_incomplete"
	CodeEFISystemPartitionMissing         = "efi_system_partition_missing"
	CodeMultipleEFISystemPartitions       = "multiple_efi_system_partitions"
	CodeEFISystemPartitionAmbiguous       = "efi_system_partition_ambiguous"
	CodeEFISystemPartitionCrossDisk       = "efi_system_partition_cross_disk"
	CodeEFISystemPartitionRelationUnknown = "efi_system_partition_relation_unknown"
	CodeEFISystemPartitionUnreadable      = "efi_system_partition_unreadable"
	CodeBCDStoreMissing                   = "bcd_store_missing"
	CodeBCDStoreAmbiguous                 = "bcd_store_ambiguous"
	CodeBCDStoreUnreadable                = "bcd_store_unreadable"
	CodeBCDMembershipUnknown              = "bcd_membership_unknown"
	CodeBCDWindowsEntryMissing            = "bcd_windows_entry_missing"
	CodeBCDPointsToUnknownInstallation    = "bcd_points_to_unknown_installation"
	CodeBCDCrossDiskMismatch              = "bcd_cross_disk_mismatch"
	CodeBitLockerLocked                   = "bitlocker_locked"
	CodeBitLockerStatusUnknown            = "bitlocker_status_unknown"
	CodeBitLockerRecoveryMaterialRequired = "bitlocker_recovery_material_required"
	CodeBitLockerBlocksBootAnalysis       = "bitlocker_blocks_boot_analysis"
	CodeStorageHealthCritical             = "storage_health_critical"
	CodeStorageHealthWarning              = "storage_health_warning"
	CodeStorageHealthUnknown              = "storage_health_unknown"
	CodeStorageEvidenceMissing            = "storage_evidence_missing"
	CodeUnsafeToAttemptBootRepair         = "unsafe_to_attempt_boot_repair"
	CodeBootTopologyIncomplete            = "boot_topology_incomplete"
	CodeBootTopologyAmbiguous             = "boot_topology_ambiguous"
	CodeBootTopologyConflicting           = "boot_topology_conflicting"
	CodeInsufficientEvidenceForRepairPlan = "insufficient_evidence_for_repair_plan"
	CodeTechnicianSelectionRequired       = "technician_selection_required"
	CodeBootTopologyConsistent            = "boot_topology_consistent"
)

// Severity and domain confidence (low|medium|high) mapping for each code.
type codeSpec struct {
	Severity   string
	Confidence string // domain Finding confidence
	Title      string
	Rationale  string
	Workflows  []string
}

func catalog() map[string]codeSpec {
	return map[string]codeSpec{
		CodeFirmwareModeUnknown: {
			Severity: "high", Confidence: "low",
			Title:     "Firmware boot mode is unknown",
			Rationale: "Evidence does not establish a single firmware boot mode, so boot-chain conclusions remain provisional.",
			Workflows: []string{"boot.inspect_firmware_mode"},
		},
		CodeFirmwareModeConflicting: {
			Severity: "high", Confidence: "high",
			Title:     "Firmware boot mode evidence conflicts",
			Rationale: "Collected firmware facts disagree (for example UEFI vs BIOS). No single boot chain may be assumed.",
			Workflows: []string{"boot.inspect_firmware_mode"},
		},
		CodeUEFIWithMBRSystemDisk: {
			Severity: "high", Confidence: "high",
			Title:     "UEFI firmware with MBR system disk",
			Rationale: "Firmware mode is UEFI while the selected or only system disk uses MBR partition style.",
			Workflows: []string{"storage.inspect_partition_layout", "boot.inspect_firmware_mode"},
		},
		CodeLegacyWithGPTLayout: {
			Severity: "medium", Confidence: "high",
			Title:     "Legacy BIOS firmware with GPT layout",
			Rationale: "Firmware mode is legacy/BIOS while disk layout is GPT, which is an unusual and often unsupported combination for this Boot Doctor profile.",
			Workflows: []string{"storage.inspect_partition_layout", "boot.inspect_firmware_mode"},
		},
		CodeUnsupportedLegacyBootTopology: {
			Severity: "high", Confidence: "medium",
			Title:     "Unsupported legacy boot topology",
			Rationale: "Automatic Boot Doctor analysis supports UEFI+GPT recovery paths; legacy BIOS topologies require technician-directed follow-up.",
			Workflows: []string{"boot.inspect_firmware_mode"},
		},
		CodeWindowsInstallationMissing: {
			Severity: "high", Confidence: "high",
			Title:     "No Windows installation target found",
			Rationale: "Topology candidates do not include a Windows installation role grounded in evidence.",
			Workflows: []string{"windows.inspect_installation"},
		},
		CodeMultipleWindowsInstallations: {
			Severity: "medium", Confidence: "high",
			Title:     "Multiple Windows installations present",
			Rationale: "More than one Windows installation candidate exists; automatic selection is not permitted.",
			Workflows: []string{"windows.inspect_installation"},
		},
		CodeWindowsInstallationAmbiguous: {
			Severity: "medium", Confidence: "low",
			Title:     "Windows installation selection is ambiguous",
			Rationale: "Windows installation candidates or relations are ambiguous and require technician selection.",
			Workflows: []string{"windows.inspect_installation"},
		},
		CodeWindowsPartitionRelationUnknown: {
			Severity: "medium", Confidence: "low",
			Title:     "Windows-to-partition relation is unknown",
			Rationale: "A Windows installation is present but its hosting partition relation is missing or not proven.",
			Workflows: []string{"windows.inspect_installation", "storage.inspect_partition_layout"},
		},
		CodeWindowsSystemDiskRelationUnknown: {
			Severity: "medium", Confidence: "low",
			Title:     "Windows partition-to-disk relation is unknown",
			Rationale: "The Windows partition cannot be related to a system disk with acceptable confidence.",
			Workflows: []string{"storage.inspect_partition_layout"},
		},
		CodeWindowsInstallationIncomplete: {
			Severity: "medium", Confidence: "medium",
			Title:     "Windows installation topology is incomplete",
			Rationale: "Windows installation evidence is present but required partition or disk roles remain unresolved.",
			Workflows: []string{"windows.inspect_installation"},
		},
		CodeEFISystemPartitionMissing: {
			Severity: "medium", Confidence: "high",
			Title:     "EFI System Partition is missing",
			Rationale: "No EFI System Partition candidate was identified from partition evidence.",
			Workflows: []string{"boot.inspect_efi_layout"},
		},
		CodeMultipleEFISystemPartitions: {
			Severity: "medium", Confidence: "high",
			Title:     "Multiple EFI System Partitions present",
			Rationale: "More than one ESP candidate exists; automatic selection is not permitted.",
			Workflows: []string{"boot.inspect_efi_layout"},
		},
		CodeEFISystemPartitionAmbiguous: {
			Severity: "medium", Confidence: "low",
			Title:     "EFI System Partition selection is ambiguous",
			Rationale: "ESP candidates or relations are ambiguous and require technician selection.",
			Workflows: []string{"boot.inspect_efi_layout"},
		},
		CodeEFISystemPartitionCrossDisk: {
			Severity: "critical", Confidence: "high",
			Title:     "EFI System Partition is on a different disk",
			Rationale: "ESP and Windows system disk roles are not connected on the same disk, creating cross-disk boot risk.",
			Workflows: []string{"boot.inspect_efi_layout", "storage.inspect_partition_layout"},
		},
		CodeEFISystemPartitionRelationUnknown: {
			Severity: "medium", Confidence: "low",
			Title:     "ESP-to-disk relation is unknown",
			Rationale: "An ESP candidate exists without a proven hosts_esp relation to the system disk.",
			Workflows: []string{"boot.inspect_efi_layout"},
		},
		CodeEFISystemPartitionUnreadable: {
			Severity: "medium", Confidence: "medium",
			Title:     "EFI System Partition evidence is unreadable",
			Rationale: "Evidence explicitly indicates the ESP could not be read; filesystem corruption is not asserted without that proof.",
			Workflows: []string{"boot.inspect_efi_layout"},
		},
		CodeBCDStoreMissing: {
			Severity: "medium", Confidence: "medium",
			Title:     "BCD store is missing",
			Rationale: "No BCD store candidate was identified for the boot topology.",
			Workflows: []string{"boot.inspect_bcd_store"},
		},
		CodeBCDStoreAmbiguous: {
			Severity: "medium", Confidence: "low",
			Title:     "BCD store selection is ambiguous",
			Rationale: "Multiple BCD store candidates or ambiguous BCD relations prevent a unique selection.",
			Workflows: []string{"boot.inspect_bcd_store"},
		},
		CodeBCDStoreUnreadable: {
			Severity: "medium", Confidence: "medium",
			Title:     "BCD store evidence is unreadable",
			Rationale: "Evidence indicates the BCD store could not be read. Corruption is not asserted from absence alone.",
			Workflows: []string{"boot.inspect_bcd_store"},
		},
		CodeBCDMembershipUnknown: {
			Severity: "medium", Confidence: "low",
			Title:     "BCD membership relative to Windows is unknown",
			Rationale: "BCD evidence does not prove membership for the selected Windows installation.",
			Workflows: []string{"boot.inspect_bcd_store"},
		},
		CodeBCDWindowsEntryMissing: {
			Severity: "medium", Confidence: "medium",
			Title:     "BCD Windows boot entry appears missing",
			Rationale: "A BCD store is present but no boot_store_for_windows relation to a known installation is established.",
			Workflows: []string{"boot.inspect_bcd_store", "windows.inspect_installation"},
		},
		CodeBCDPointsToUnknownInstallation: {
			Severity: "medium", Confidence: "medium",
			Title:     "BCD points to an unknown Windows installation",
			Rationale: "BCD relations reference a Windows target that is not present among topology candidates.",
			Workflows: []string{"boot.inspect_bcd_store", "windows.inspect_installation"},
		},
		CodeBCDCrossDiskMismatch: {
			Severity: "critical", Confidence: "high",
			Title:     "BCD store is on a mismatched disk",
			Rationale: "BCD containment relations place the store outside the selected Windows/ESP disk chain.",
			Workflows: []string{"boot.inspect_bcd_store", "storage.inspect_partition_layout"},
		},
		CodeBitLockerLocked: {
			Severity: "high", Confidence: "high",
			Title:     "BitLocker volume is locked",
			Rationale: "BitLocker evidence reports a locked or inaccessible volume. Filesystem damage is not inferred from inaccessibility alone.",
			Workflows: []string{"bitlocker.inspect_inventory"},
		},
		CodeBitLockerStatusUnknown: {
			Severity: "high", Confidence: "low",
			Title:     "BitLocker status is unknown",
			Rationale: "BitLocker evidence is present but lock/protection status is empty or unrecognized and is not treated as safe.",
			Workflows: []string{"bitlocker.inspect_inventory"},
		},
		CodeBitLockerRecoveryMaterialRequired: {
			Severity: "high", Confidence: "medium",
			Title:     "BitLocker recovery material is required",
			Rationale: "Locked BitLocker state blocks further boot-path inspection until recovery material is supplied out of band. Recovery secrets are never stored in Findings.",
			Workflows: []string{"bitlocker.inspect_inventory"},
		},
		CodeBitLockerBlocksBootAnalysis: {
			Severity: "high", Confidence: "high",
			Title:     "BitLocker blocks boot analysis",
			Rationale: "BitLocker inaccessibility prevents complete boot topology analysis of protected volumes.",
			Workflows: []string{"bitlocker.inspect_inventory"},
		},
		CodeStorageHealthCritical: {
			Severity: "critical", Confidence: "high",
			Title:     "Storage health is critical",
			Rationale: "Drive health evidence reports failed, unhealthy, or critical status. Boot repair must be treated as unsafe.",
			Workflows: []string{"storage.inspect_disk_health"},
		},
		CodeStorageHealthWarning: {
			Severity: "medium", Confidence: "medium",
			Title:     "Storage health warning",
			Rationale: "Drive health evidence reports a non-critical warning condition that lowers repair confidence.",
			Workflows: []string{"storage.inspect_disk_health"},
		},
		CodeStorageHealthUnknown: {
			Severity: "high", Confidence: "low",
			Title:     "Storage health is unknown",
			Rationale: "Storage health status is missing or unrecognized and is not treated as healthy.",
			Workflows: []string{"storage.inspect_disk_health"},
		},
		CodeStorageEvidenceMissing: {
			Severity: "high", Confidence: "low",
			Title:     "Storage health evidence is missing",
			Rationale: "No drive-health evidence records were available for topology eligibility diagnostics.",
			Workflows: []string{"storage.inspect_disk_health"},
		},
		CodeUnsafeToAttemptBootRepair: {
			Severity: "critical", Confidence: "high",
			Title:     "Unsafe to attempt boot repair",
			Rationale: "Critical storage health or cross-disk destructive-risk topology makes boot repair unsafe based on current evidence.",
			Workflows: []string{"storage.inspect_disk_health", "case.verify_store_integrity"},
		},
		CodeBootTopologyIncomplete: {
			Severity: "medium", Confidence: "medium",
			Title:     "Boot topology is incomplete",
			Rationale: "Required boot roles or relations are missing, so a repair plan cannot be justified yet.",
			Workflows: []string{"boot.inspect_efi_layout", "windows.inspect_installation"},
		},
		CodeBootTopologyAmbiguous: {
			Severity: "medium", Confidence: "low",
			Title:     "Boot topology is ambiguous",
			Rationale: "Multiple candidates or ambiguous relations prevent selecting a single boot chain.",
			Workflows: []string{},
		},
		CodeBootTopologyConflicting: {
			Severity: "high", Confidence: "high",
			Title:     "Boot topology evidence conflicts",
			Rationale: "Topology ambiguities or firmware conflicts contradict a single coherent boot chain.",
			Workflows: []string{"boot.inspect_firmware_mode"},
		},
		CodeInsufficientEvidenceForRepairPlan: {
			Severity: "medium", Confidence: "low",
			Title:     "Insufficient evidence for a repair plan",
			Rationale: "Current evidence and topology blockers are insufficient to justify any typed repair plan.",
			Workflows: []string{"case.verify_store_integrity"},
		},
		CodeTechnicianSelectionRequired: {
			Severity: "medium", Confidence: "medium",
			Title:     "Technician selection is required",
			Rationale: "Automatic topology selection is unavailable; a complete connected technician selection is required.",
			Workflows: []string{},
		},
		CodeBootTopologyConsistent: {
			Severity: "info", Confidence: "high",
			Title:     "Boot topology is consistent",
			Rationale: "Topology roles are unique, relations are proven or strong, firmware is consistent, BitLocker does not block, and storage health is known and non-critical.",
			Workflows: []string{},
		},
	}
}
