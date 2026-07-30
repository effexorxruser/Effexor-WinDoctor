# Read-only operation registry (PR #18)

Status: **typed local registry**. Executes catalogued read-only observations
against Case snapshot evidence (and Case Store Verify for integrity). No
`os/exec`, shell, PowerShell, WMI subprocess, or arbitrary executables.

## Package

`internal/recovery/operations/read`

Descriptors reuse `operation-descriptor` 1.0.0. Request/result envelopes:

- `read-operation-request` 1.0.0 (`readreq-<24 hex>`)
- `read-operation-result` 1.0.0

## Catalog (all `1.0.0`, `risk_class=read_only`, `mutation_class=none`)

| Operation | Observation source |
|-----------|-------------------|
| `windows.inspect_installation` | `case_snapshot` |
| `boot.inspect_firmware_mode` | `case_snapshot` |
| `boot.inspect_bcd_store` | `case_snapshot` |
| `boot.inspect_efi_layout` | `case_snapshot` |
| `storage.inspect_disk_health` | `case_snapshot` |
| `storage.inspect_partition_layout` | `case_snapshot` |
| `bitlocker.inspect_inventory` | `case_snapshot` |
| `case.verify_store_integrity` | `case_store` |

The first seven normalize stored Case evidence. They do **not** claim live
Windows reinspection. `case.verify_store_integrity` calls real Case Store Verify.

## Safety

Registry construction rejects non-read-only descriptors, missing handlers,
duplicates, and missing schema refs. Execute rejects unknown ops/versions, wrong
target types, unknown parameters, cancelled context, and mismatched results.

Successful/partial results convert to EvidenceBundles with deterministic
EvidenceIDs (wall clock excluded from ID hashing).

## Explicit non-claims

- No mutating operations, backup, approval, planner, gateway, or UI.
- No provider-defined or file-loaded descriptors.
- Live native Windows readers are a future extension after contracts stabilize.
