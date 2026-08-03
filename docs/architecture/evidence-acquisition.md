# Evidence acquisition (PR #18)

Status: **library contracts + Case Store validation**. Incremental Targets and
Evidence after Case creation use immutable provenance records. This is not live
Windows reinspection and is not mutation authority.

## Why

PR #17 required the revision-1 `case_created` / `legacy_case_adopted` event to
reference every Target and Evidence ID in the snapshot. That rule cannot survive
post-create observations: any new Evidence would invalidate history.

## Contract

`evidence-acquisition-record` 1.0.0

Canonical Case Store path:

`documents/evidence-acquisitions/<acquisition_id>.json`

ID format: `acq-<24 lowercase hex>`  
Request ID format: `acqreq-<24 lowercase hex>`

## Origin coverage

- Without `EvidenceAcquisitions`, revision-1 create/adopt refs must cover **all**
  Target/Evidence IDs (PR #17 compatibility).
- With acquisitions present, revision-1 covers **initial** IDs only; each later
  ID has origin in exactly one acquisition record.
- Sets are disjoint: an ID cannot be both initial and added, or claimed twice.

## Coordinator semantics (PR #18)

`ExecuteReadOperation` and `ResolveWindowsBootTopology`:

- allowed only in `evidence_collected`;
- verify Case Store integrity and expected commit;
- append Evidence (+ optional Targets) and one acquisition record;
- do **not** change WorkflowState, WorkflowRevision, CoordinatorEvents, or
  `CaseManifest.CurrentState`;
- commit once via Atomic Case Store;
- idempotent on identical `request_id` + canonical request;
- divergent same `request_id` → typed conflict.

Acquisition timestamps live on the record and CommitInfo; WorkflowState.UpdatedAt
is not advanced for read-only observation.

## Explicit non-claims

- Not an approval, RepairPlan, or execution event.
- Does not authorize mutation.
- Live probe collectors are out of scope for PR #18.
