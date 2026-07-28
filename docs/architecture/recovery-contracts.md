# Recovery domain contracts (1.0.0)

This document describes the first Effexor Recovery Platform domain contracts.
They are **documentation and typed data only**. This PR does not implement a
case store, planner, operation executor, Boot Doctor, or mutation path.

## Contract responsibilities

| Contract | Responsibility |
|----------|----------------|
| `case-manifest` | Case lifecycle envelope and privacy class |
| `target` | Stable recovery target identity (not drive-letter identity) |
| `evidence-bundle` | Collector evidence for one target, with extensible `facts` |
| `finding` | Interpreted conclusion grounded in evidence |
| `repair-plan` | Ordered typed operation steps (document only) |
| `operation-descriptor` | Typed operation metadata; **no commands** |
| `execution-event` | Audit record of an operation attempt |
| `verification-report` | Post-operation verification outcome |
| `common` | Shared ID, hash, path, and `ArtifactRef` definitions |

Go types live in `internal/recovery/domain`.
JSON Schema compilation helpers live in `internal/recovery/validation`.
Fixtures live in `fixtures/recovery/{valid,invalid}`.

## Legacy diagnostic-report importer

A pure importer maps collector `diagnostic-report` 1.3.0 into
`CaseManifest` / `Target` / `EvidenceBundle` documents. See
[`legacy-report-importer.md`](./legacy-report-importer.md).
It does not write Case Store files, create Findings, or execute operations.

## Envelope strictness

Every document envelope uses JSON Schema Draft 2020-12 with
`additionalProperties: false`. Unknown top-level fields are rejected by schema
validation and by Go `DisallowUnknownFields` decoding.

Timestamps are RFC3339. SHA-256 values are exactly 64 hex characters.
`ArtifactRef.relative_path` forbids absolute paths and `../` traversal.

## Intentional extension points

- `EvidenceBundle.facts` is `json.RawMessage` / schema `{}` so collectors can
  carry typed payloads without widening the envelope.
- Optional `facts_schema` names the facts payload contract for future
  collector-specific validation.
- Operation parameters/results are referenced by schema refs on
  `OperationDescriptor`, not inlined as free-form command text.

## ID and reference rules

IDs follow documented patterns (`case-…`, `target-…`, `evidence-…`, etc.).

Cross-document references are enforced in Go (`Validate*Refs`) because JSON
Schema validates one document at a time:

| Method | Checks |
|--------|--------|
| `Finding.ValidateFindingRefs` | `case_id`, each `evidence_ref`, each `affected_target_id` |
| `RepairPlan.ValidatePlanRefs` | `case_id`, each `finding_ref`, each step `target_id` |
| `EvidenceBundle.ValidateEvidenceRefs` | `case_id`, `target_id` |
| `ExecutionEvent.ValidateExecutionRefs` | `case_id`, `target_id`, optional `stdout_artifact` / `stderr_artifact` |
| `VerificationReport.ValidateVerificationRefs` | `case_id`, `execution_id`, each `evidence_ref` |

Operation references always use `operation_id` + `version`.

## RepairPlan dependency rules

`steps` are ordered. Primary invariant: every `depends_on` entry must **precede**
the current step in that array. Derived rules:

- no duplicate IDs inside one step's `depends_on`
- no self-dependency
- no forward dependency
- cycles are impossible under the precede rule (and rejected via forward edges)

## OperationDescriptor safety invariants

| Risk class | Required constraints |
|------------|----------------------|
| `read_only` | `mutation_class=none`, `requires_backup=false` |
| non-`read_only` | `mutation_class != none` |
| `controlled_mutation` / `destructive` / `irreversible` | `requires_explicit_approval=true` |
| `irreversible` | `rollback_quality=unavailable` |
| `reversible` | `rollback_quality != unavailable` |

These rules are enforced in Go `Validate()` and mirrored as JSON Schema
`if`/`then` constraints.

## ExecutionEvent lifecycle

| Status | `completed_at` | `exit_code` | `error` |
|--------|----------------|-------------|--------|
| `started` | absent or `null` | must be `null` | optional |
| `succeeded` | required RFC3339 | optional integer/null | absent or empty |
| `failed` / `timed_out` | required RFC3339 | optional integer/null | **required**, non-empty |
| `cancelled` | required RFC3339 | optional integer/null | optional |

## Finding evidence rule

If `evidence_refs` is empty, `insufficient_evidence` must be `true`
(Go + JSON Schema).

## Schema / Go parity

Single-document fixtures are validated by both JSON Schema and Go and must
agree on accept/reject, except **documented Go-only cross-document / graph
rules**:

- repair-plan dependency graph (precede / self / forward / duplicate / unknown)
- `Validate*Refs` existence checks across documents

## Schema versioning

Every document includes:

- `schema_name`
- `schema_version` (`1.0.0` for this release)

These contracts intentionally do **not** reuse `diagnostic-report` 1.3.0 naming.

## Relationship with diagnostic-report 1.3.0

`contracts/diagnostic-report.schema.json` remains the current collector report
contract and is unchanged by this work. Recovery contracts sit beside it under
`contracts/recovery/`.

A future importer (planned around tentative PR #15 / roadmap R1 follow-on) may
map selected diagnostic-report fields into `EvidenceBundle` / `Target` documents.
That importer is **out of scope** here.

## Why no commands or executors

`OperationDescriptor` deliberately omits command, PowerShell, argv, and
executable fields. Recovery Core must remain typed and policy-bound. Raw model
or UI command strings cannot be represented by these contracts.
