# Boot Doctor Finding catalog

Machine codes are stored as `finding_code:<code>` on Finding limitations.

| Code | Severity | Typical confidence | Notes |
|------|----------|--------------------|-------|
| `firmware_mode_unknown` | high | low | No single firmware mode |
| `firmware_mode_conflicting` | high | high | UEFI vs BIOS disagreement |
| `uefi_with_mbr_system_disk` | high | high | UEFI + MBR |
| `legacy_with_gpt_layout` | medium | high | BIOS + GPT |
| `unsupported_legacy_boot_topology` | high | medium | Legacy path unsupported for auto repair planning |
| `windows_installation_missing` | high | high | No Windows role |
| `multiple_windows_installations` | medium | high | >1 Windows |
| `windows_installation_ambiguous` | medium | low | Ambiguous Windows selection |
| `windows_partition_relation_unknown` | medium | low | Windows↔partition unproven |
| `windows_system_disk_relation_unknown` | medium | low | Partition↔disk unproven |
| `windows_installation_incomplete` | medium | medium | Incomplete Windows roles |
| `efi_system_partition_missing` | medium | high | No ESP |
| `multiple_efi_system_partitions` | medium | high | >1 ESP |
| `efi_system_partition_ambiguous` | medium | low | Ambiguous ESP |
| `efi_system_partition_cross_disk` | critical | high | ESP on other disk |
| `efi_system_partition_relation_unknown` | medium | low | ESP↔disk unproven |
| `efi_system_partition_unreadable` | medium | medium | Only with proving Evidence |
| `bcd_store_missing` | medium | medium | No BCD candidate |
| `bcd_store_ambiguous` | medium | low | Multiple/ambiguous BCD |
| `bcd_store_unreadable` | medium | medium | Unreadable BCD Evidence |
| `bcd_membership_unknown` | medium | low | BCD↔Windows unknown |
| `bcd_windows_entry_missing` | medium | medium | No boot_store_for_windows |
| `bcd_points_to_unknown_installation` | medium | medium | BCD→unknown Windows |
| `bcd_cross_disk_mismatch` | critical | high | BCD outside selected chain |
| `bitlocker_locked` | high | high | Locked/inaccessible |
| `bitlocker_status_unknown` | high | low | Empty/unrecognized status |
| `bitlocker_recovery_material_required` | high | medium | Out-of-band material; secrets never stored |
| `bitlocker_blocks_boot_analysis` | high | high | Analysis incomplete due to BitLocker |
| `storage_health_critical` | critical | high | Failed/unhealthy/critical |
| `storage_health_warning` | medium | medium | Non-critical warning |
| `storage_health_unknown` | high | low | Unknown ≠ healthy |
| `storage_evidence_missing` | high | low | No health records |
| `unsafe_to_attempt_boot_repair` | critical | high | Diagnostic unsafe signal only |
| `boot_topology_incomplete` | medium | medium | Missing roles/relations |
| `boot_topology_ambiguous` | medium | low | Multiple candidates |
| `boot_topology_conflicting` | high | high | Contradictory chain |
| `insufficient_evidence_for_repair_plan` | medium | low | No repair plan justified |
| `technician_selection_required` | medium | medium | Automatic selection unavailable |
| `boot_topology_consistent` | info | high | Healthy baseline only when fully proven |

Findings are **not** approvals. `mutation_eligibility` remains diagnostic only.
