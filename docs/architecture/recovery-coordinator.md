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
| `AdoptLegacyCase` | Attach workflow to a pure legacy Case/Target/Evidence snapshot |
| `CommitAnalysis` | Append Findings → `analyzed` (refresh `analyzed → analyzed` allowed) |
| `CommitPlan` | Persist **draft** RepairPlan → `plan_proposed` |
| `FailCase` | Transition to `failed` |
| `CancelCase` | Transition to `cancelled` |

`CreateCase` requires an absent Case head (`ParentExpectationAbsent`). A second
create for the same report hash returns `ErrCaseAlreadyExists` and does not
append snapshots or reset workflow. Use `AdoptLegacyCase` to migrate legacy
snapshots; never treat `CreateCase` as migration.

`AdoptLegacyCase` is allowed only when WorkflowState is absent,
`CaseManifest.current_state == SNAPSHOTTED`, CoordinatorEvents / Findings /
RepairPlans / ExecutionEvents / VerificationReports are empty, and Targets plus
Evidence are present.

`CommitPlan` accepts only `status=draft` with at least one finding_ref and one
step (Coordinator policy for PR #17; RepairPlan contract unchanged).

Write methods return the **exact committed revision** (input Snapshot +
CommitInfo). They do not `LoadLatest` after Commit, so a concurrent writer
cannot alter the returned view.

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

### Event revision model

All `coordinator-event` 1.0.0 events in PR #17 are state-changing and carry
explicit `workflow_revision` (integer ≥ 1):

- revision `1` must be `case_created` or `legacy_case_adopted`;
- for each revision `2..N`, `current.previous_state == previous.next_state`;
- revisions are unique and form the contiguous sequence `1..WorkflowState.Revision`;
- `last_transition_id` must reference the event with the **maximum** revision;
- the maximum revision `next_state` must equal `WorkflowState.State`;
- ordering does **not** depend on `occurred_at` or `event_id`.

The immutable event semantics table is shared by Coordinator writes and Case
Store snapshot validation, so actor authority and state-transition rules cannot
drift between writer and reader.

Persisted workflow-state semantics are also validated centrally:

- legacy latest snapshots may contain only Case / Targets / Evidence with `WorkflowState=nil`;
- once workflow exists, Findings / RepairPlans / ExecutionEvents /
  VerificationReports / CoordinatorEvents require it;
- `created` and all future reserved states are rejected as persisted latest
  states in PR #17;
- `WorkflowState.updated_at == CaseManifest.updated_at == last_transition.occurred_at`;
- `plan_proposed` requires `active_plan_id`; `failed` requires `failure`;
- all PR #17 states forbid `active_execution_id`.

### Event-specific refs

Audit events reference only documents relevant to that command (not the full
latest document set):

| Event | Refs |
|-------|------|
| CreateCase / AdoptLegacyCase | Case, Targets, Evidence, workflow singleton |
| CommitAnalysis | Case, Findings from this command, their Evidence/Target refs, workflow singleton |
| CommitPlan | Case, Plan, plan.finding_refs, step target IDs, workflow singleton |
| Fail / Cancel | Case, workflow singleton, active plan ID when present |

### Append-only Findings

Findings referenced by audit are append-only across CommitAnalysis calls:

- existing Findings are retained;
- new Finding IDs are appended;
- duplicate FindingID with identical canonical content is a no-op;
- duplicate FindingID with divergent content is rejected.

### Immutable RepairPlans

`RepairPlan` documents are immutable by `plan_id`:

- a new `plan_id` appends;
- reusing the same `plan_id` with identical canonical JSON is a no-op;
- reusing the same `plan_id` with divergent content is rejected.

### Resulting IDs

Authoritative `snapshot_id` / `commit_id` for a write live on Case Store
`CommitInfo` / commit-record. They are **not** embedded on coordinator-event
(circular with content-addressed snapshot hashing).

PR #17 actors permitted to transition state:

- `system`
- `technician`
- `deterministic_analyzer`

State-changing audit `expected_commit_id` policy:

- `case_created` at revision `1`: absent;
- `legacy_case_adopted` at revision `1`: required;
- revisions `> 1`: required.

## Timestamps

Coordinator timestamps are monotonic relative to `Case.CreatedAt`,
`Case.UpdatedAt`, and `WorkflowState.UpdatedAt`. WinPE wall clock alone is not
trusted.

## Idempotency

PR #17 relies on Case Store snapshot-id idempotent Commit: retrying an
identical canonical Snapshot against the current head is safe (except
create-only absent-parent commits). Full command-level idempotency
(command_id + payload) is **not** claimed; optional `command_id` may be
recorded on audit events for later use.

## Dependencies

Injected interfaces only:

- Case Store (`Commit`, `LoadLatest`, `Verify`)
- Legacy importer (`ImportJSON`)
- Clock / IDSource

No gateway, agent-loop, or executor imports.
