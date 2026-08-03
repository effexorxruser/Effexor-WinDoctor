# Repair Planner

Status: **PR #21** — deterministic draft `RepairPlan` generation only.

## Inputs

- Verified Case snapshot (`analyzed`)
- Persisted Windows boot topology evidence
- Deterministic Findings (Boot Doctor)
- Optional advisory Agent Consultation (ignored for authority)
- Local planned operation registry (`internal/recovery/operations/planned`)
- Planner version (`1.0.0`)

## Output

- Draft `RepairPlan` 1.0.0, **or**
- Typed refusal with stable reason codes

## Supported first candidate

Conservative UEFI/GPT single-Windows topology with:

- one proven Windows installation / partition / system disk / ESP
- BitLocker not blocking
- storage health known and not critical
- a Boot Doctor BCD repair Finding

All other topologies refuse (including Legacy/BIOS/MBR).

## Hard non-goals

- No operation execution
- No raw commands from models
- No clearing topology blockers
- No self-approval
- No backup artifact creation

## Identity

Plan ID is derived from a digest of planner version, Case ID, source commit,
topology ID, sorted Finding IDs, and the canonical operation graph. Timestamps
do not participate.
