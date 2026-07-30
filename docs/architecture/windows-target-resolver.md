# Windows target resolver (PR #18)

Status: **deterministic advisory library**. Builds a Windows boot topology
EvidenceBundle from Case snapshot evidence. Does not write Case Store directly,
create Findings, or perform mutation.

## Package

`internal/recovery/targetresolver`

Facts schema: `windows-boot-topology` 1.0.0  
Collector: `effexor-recovery-target-resolver`

## Guarantees

- Deterministic IDs and ordering for identical canonical input.
- Drive letters are runtime-only; never stable identity; never `proven`.
- Conflicting or missing evidence surfaces as unknown/ambiguous/conflicting —
  never silently chosen as healthy.
- `mutation_eligibility` is advisory diagnostic completeness only. It is **not**
  approval, RepairPlan, or safe-to-repair proof.

## Selection

Automatic selection requires a unique UEFI+GPT topology with one Windows
installation, one linked partition/disk, unique ESP, and non-conflicting
relations. Otherwise `selection.source = none` and blockers are recorded.

Technician selection may pin candidate IDs but cannot clear firmware, BitLocker,
unsafe storage, or missing-evidence blockers.

## Persistence

Coordinator `ResolveWindowsBootTopology` persists topology as Evidence with an
`EvidenceAcquisitionRecord`. Workflow revision is unchanged.

## Explicit non-claims

- Boot Doctor is absent.
- No BCD/EFI mutation.
- No live Windows reinspection in PR #18.
- No LLM authority.
