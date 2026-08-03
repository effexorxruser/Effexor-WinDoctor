# Recovery Policy Engine

Status: **PR #21** — independent gate for draft RepairPlans.

## Independence

The Policy Engine does **not** trust the Planner. It re-validates:

- Case Store integrity (via Coordinator load gate)
- plan/case/commit binding
- topology blockers and firmware mode
- Finding / Target / Evidence refs
- local planned operation descriptors
- backup, verification, and approval declarations
- absence of command-like fields
- DAG / ordered-step validity

## Decisions

- `allowed`
- `denied`
- `needs_more_evidence`

`allowed` only means the draft plan is coherent enough to await explicit
technician approval. It does **not** authorize execution.

## Persistence

Immutable `policy-evaluation` 1.0.0 documents are stored under
`policy-evaluations/`. Allowed evaluations advance workflow
`plan_proposed → awaiting_approval`. Denied / needs-more-evidence evaluations
are appended without advancing workflow.
