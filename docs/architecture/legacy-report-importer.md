# Legacy diagnostic-report importer

Pure, deterministic transform from collector `diagnostic-report` **1.3.0** into
Recovery Platform domain documents:

- `CaseManifest`
- `Target[]`
- `EvidenceBundle[]`

Package: `internal/recovery/importer/legacyreport`.

This importer does **not** implement Case Store, Findings, RepairPlan, CLI,
filesystem persistence, operations, or mutations.

## Input / output

```text
diagnostic-report 1.3.0 JSON bytes
        │
        ▼
legacyreport.ImportJSON(raw, Options)
        │
        ▼
Result{ Case, Targets, EvidenceBundles, Warnings }
```

`Options.SourceArtifact`, when provided, is validated and attached to every
generated EvidenceBundle `artifacts` array. No files are read or written.

## Why schema 1.2.0 is rejected here

`diagnostics.DecodeReportJSON` can migrate 1.2.0 → 1.3.0. This importer
intentionally refuses 1.2.0 **before** decode so provenance of an old wire
format is not hidden. A future explicit versioned migration path may be added
separately.

## Deterministic ID generation

| ID | Formula |
|----|---------|
| `raw_source_sha256` | SHA-256 of input bytes |
| `normalized_report_sha256` | decode report → `json.Marshal(report)` → SHA-256 |
| `case_id` | `case-` + first 24 hex of normalized hash |
| `target_id` | `target-` + first 24 hex of SHA-256(`case_id` + NUL + `source_path`) |
| `evidence_id` | `evidence-` + first 24 hex of SHA-256(`case_id` + NUL + `target_id` + NUL + facts schema version) |

No random UUIDs. No `time.Now()`. Whitespace-only JSON changes do not change
normalized IDs. Semantic report changes do.

## Target mapping

Ordered result:

1. firmware / host environment (one)
2. disks (`storage.disks[n]`)
3. partitions (`storage.partitions[n]`)
4. Windows installations
5. boot stores (`boot.bcd_stores[n]`)
6. BitLocker volumes only when inventory status is `ok` or `partial`

## Identity limitations

Legacy 1.3.0 lacks reliable disk serial / partition GUID / volume GUID.
Each Target uses report-scoped `stable_identity`:

- `legacy_report_hash`
- `legacy_source_path`
- `legacy_entity_fingerprint`

Every such Target carries an explicit limitation that identity is scoped to the
imported report and is not guaranteed across collection runs.

Drive letters and mount paths are **runtime locators only**, never identity.

## Runtime locator policy

Invalid / omitted locators:

- empty string
- NUL (`\u0000`)
- whitespace-only

Valid single drive letters may appear on partitions as `drive_letter`.
The same empty/NUL/whitespace policy applies to Windows
`root` / `system_hive` / `software_hive`, BCD `path` / `kind`, and BitLocker
`mount_point`. Discarded values produce an explicit limitation.

## SourceArtifact binding

When `Options.SourceArtifact` is provided it must:

- pass `ArtifactRef.Validate()`
- have `sha256` equal to SHA-256 of the raw input bytes
- have `size_bytes` equal to `len(raw)`

## Source status semantics

`source_status` reflects evidence quality for the fragment, not machine health.

- firmware / disk / partition / windows / boot → `ok` when present and valid
- BitLocker volume → `ok` when inventory is `ok`; `partial` when inventory is `partial`
- check warnings / drive health warnings do **not** force `partial`

## BitLocker handling

| Inventory status | Volume targets | Notes |
|------------------|----------------|-------|
| `unavailable` | none | inventory status/error kept in firmware evidence + limitation |
| `ok` / `partial` | one per volume | volume evidence status mirrors inventory |

## Relationship rules

Reliable:

- partition → disk via `disk_number` **only when exactly one disk target**
  shares that number (duplicate disk numbers omit the relation with a warning)

Runtime-only (only when exactly one partition matches the letter):

- Windows root drive letter → partition
- BCD path drive letter → partition
- BitLocker mount point → partition

Ambiguous or missing matches omit the relation and emit a warning/limitation.
Drive health is **not** linked to disks by friendly name.

## Privacy behavior

- `contains_personal_data=false` → `privacy_class=standard`
- `contains_personal_data=true` → `privacy_class=elevated`

Runtime mapping: `winpe` / `windows` / otherwise `unknown`.
`runtime_os=windows` is **not** reinterpreted as WinPE.

## Why checks are not Findings

Checks remain inside firmware evidence payload. Findings require interpreted
conclusions, evidence grounding, and workflow policy. This importer only
snapshots collector facts into recovery documents.

## Facts contract

Facts use:

`contracts/recovery/facts/legacy-diagnostic-report-fragment-1.0.0/`

Each EvidenceBundle carries one fragment for its Target (not the entire report
duplicated). Production `Result.Validate()` and `factsEnvelope.Validate()` are
pure Go checks and do not read the schema file from disk. JSON Schema
compilation remains a test-only concern.

## Next Case Store iteration

A future Case Store layer should persist these documents (and later Findings /
plans) as case-local artifacts. This importer only produces in-memory Result
values for that store to consume.
