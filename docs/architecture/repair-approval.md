# Repair Approval

Status: **PR #21** — explicit technician binding to an immutable plan digest.

## Meaning

Approval means:

> The technician confirmed a specific immutable RepairPlan and its bound
> policy evaluation digests.

Approval does **not** mean:

- backup already exists
- mutation may run now
- future executor gates may be skipped

## Binding

`repair-approval` 1.0.0 binds:

- Case ID
- Plan ID
- canonical plan digest
- policy evaluation ID + policy digest
- source commit ID
- optional topology ID
- technician identity reference (no secrets)

Any plan byte change invalidates the approval binding.

## Workflow

Coordinator transition:

```text
awaiting_approval → approved
```

via `approval_committed`. The Case remains non-mutating. PR #22 / #23 add
backup and typed execution gates.
