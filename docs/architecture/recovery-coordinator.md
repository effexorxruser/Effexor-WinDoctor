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
| `CreateCase` | Import diagnostic-report 1.3.0 → commit initial snapshot at `evidence_collected` (**create-only**) |
| `LoadCase` | Verify Case Store integrity → return latest `CaseView` (read-only) |
| `AdoptLegacyCase` | Attach workflow to a legacy Case/Target/Evidence snapshot |
| `CommitAnalysis` | Persist Findings → `analyzed` (refresh `analyzed → analyzed` allowed) |
| `CommitPlan` | Persist **draft** RepairPlan → `plan_proposed` |
| `FailCase` | Transition to `failed` |
| `CancelCase` | Transition to `cancelled` |

`CreateCase` requires an absent Case head (`ParentExpectationAbsent`). A second
create for the same report hash returns `ErrCaseAlreadyExists` and does not
append snapshots or reset workflow. Use `AdoptLegacyCase` to migrate legacy
snapshots; never treat `CreateCase` as migration.

`CommitPlan` accepts only `status=draft` with at least one finding_ref and one
step (Coordinator policy for PR #17; RepairPlan contract unchanged).

## Workflow ↔ CaseManifest sync

Coordinator updates both documents together:

| WorkflowState | CaseManifest.current_state |
|---------------|----------------------------|
| created | NEW |
| evidence_collected | SNAPSHOTTED |
| analyzed | DIAGNOSED |
| plan_proposed | PLANNED |
| failed | FAILED |
| cancelled | CANCELLED |

Incompatible pairs are rejected by Snapshot validation.

## Optimistic concurrency / busy

State-changing methods require `ExpectedCommitID` and pass
`ParentExpectationCommit` into Case Store. Mismatch → `ErrCaseRevisionConflict`.

If Case Store returns `ErrCaseLocked`:
- when latest head differs from expected → `ErrCaseRevisionConflict`
- when head is unchanged → `ErrCaseBusy`

## Audit

Immutable `coordinator-event` 1.0.0 documents are stored under
`documents/coordinator-events/<event_id>.json` inside each snapshot. There is
no separate mutable log.

Referenced document IDs must resolve to Case/Target/Evidence/Finding/Plan/
Execution/Verification IDs or the singleton `case-workflow-state` document id.
Duplicates and empty refs are rejected.

Revision model: `WorkflowState.Revision` equals the count of state-changing
coordinator events; `last_transition_id` is the latest such event.

PR #17 actors permitted to transition state:

- `system`
- `technician`
- `deterministic_analyzer`

## Timestamps

Coordinator timestamps are monotonic relative to `Case.CreatedAt`,
`Case.UpdatedAt`, and `WorkflowState.UpdatedAt`. WinPE wall clock alone is not
trusted.

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
