# Recovery Coordinator

Local non-mutating orchestration API for Effexor Recovery Platform cases.

Package: `internal/recovery/coordinator`.

## Purpose

The Recovery Coordinator is the only authority allowed to change Recovery Case
workflow state. UI, CLI, and gateway clients submit typed requests; the
Coordinator validates transitions, commits immutable Case Store snapshots, and
records typed audit events.

This package does **not**:

- resolve Windows boot topology;
- run Boot Doctor rules;
- call the model gateway;
- approve, back up, or execute repairs;
- expose a CLI or GUI.

## Public operations (PR #17)

| Method | Effect |
|--------|--------|
| `CreateCase` | Import diagnostic-report 1.3.0 → commit initial snapshot at `evidence_collected` |
| `LoadCase` | Verify Case Store integrity → return latest `CaseView` |
| `CommitAnalysis` | Persist Findings → `analyzed` (refresh `analyzed → analyzed` allowed) |
| `CommitPlan` | Persist RepairPlan → `plan_proposed` |
| `FailCase` | Transition to `failed` |
| `CancelCase` | Transition to `cancelled` |

## Workflow state

Coordinator-owned state lives in companion document `case-workflow-state` 1.0.0
(`documents/case-workflow-state.json`). It is **not** a silent widening of
`case-manifest` 1.0.0 / `current_state`.

PR #17 implements only:

- `created → evidence_collected` (during CreateCase)
- `evidence_collected → analyzed`
- `analyzed → analyzed`
- `analyzed → plan_proposed`
- `{created,evidence_collected,analyzed,plan_proposed} → failed|cancelled`

Later states exist in the contract enum for forward compatibility.

## Audit

Immutable `coordinator-event` 1.0.0 documents are stored under
`documents/coordinator-events/<event_id>.json` inside each snapshot. There is
no separate mutable log.

PR #17 actors permitted to transition state:

- `system`
- `technician`
- `deterministic_analyzer`

## Optimistic concurrency

State-changing methods require `ExpectedCommitID`. The Coordinator loads the
latest commit, compares IDs, and passes `ExpectedParentCommitID` into Case
Store `Commit`. Mismatch returns typed `ErrCaseRevisionConflict`. Competing
updates are never merged.

## Idempotency

PR #17 relies on Case Store snapshot-id idempotent Commit: retrying an
identical canonical Snapshot against the current head is safe. Full
command-level idempotency (command_id + payload) is **not** claimed; optional
`command_id` may be recorded on audit events for later use.

## Dependencies

Injected interfaces only:

- Case Store (`Commit`, `LoadLatest`, `Verify`)
- Legacy importer (`ImportJSON`)
- Clock / IDSource

No gateway, agent-loop, or executor imports.
