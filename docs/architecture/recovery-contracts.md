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
Cross-document references (finding → evidence/target, plan → finding/target)
receive Go validation where JSON Schema alone cannot see other documents.

Operation references always use `operation_id` + `version`.

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
