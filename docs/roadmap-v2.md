# Roadmap v2 — Effexor Recovery Platform

This roadmap reframes delivery as platform slices. Numbers **R0–R11** are an
ordered delivery sequence. Any associated pull-request numbers below are
**tentative labels for planning only**, not reserved GitHub PR IDs and not a
promise that those numbers will match reality.

The historical milestone roadmap remains in [`roadmap.md`](roadmap.md) for
traceability of what already shipped under the EffexorWinPE MVP framing.

## Principles

- Documentation and contracts before mutations.
- EffexorWinPE remains a profile; Recovery Core is the long-term center.
- Desktop shell is an optional parallel UX track and must not gate Core.
- Do not claim Boot Doctor, mutation ops, case store, or Hub as shipped until
  they exist in code.

## Sequence

| Slice | Tentative PR label | Intent | Status |
|-------|--------------------|--------|--------|
| **R0** | ~foundation docs | Product boundary, glossary, ADRs, overview | Completed |
| **R1** | ~domain contracts | Shared typed contracts for evidence/finding/plan/operation | Completed |
| — | ~legacy importer bridge | diagnostic-report 1.3.0 → Case/Target/Evidence | Completed |
| **R2** | ~Case Store / coordinator foundation | Local persistence + orchestration API that cannot mutate yet | Case Store in progress |
| **R3** | ~Boot Doctor read path | First vertical: boot evidence → findings only | Not started |
| **R4** | ~policy + approval surface | Explicit local approval records; UI cannot bypass | Not started |
| **R5** | ~typed read ops expansion | More read-only operations under policy | Not started |
| **R6** | ~backup primitives | Backup/rollback material before any mutation | Not started |
| **R7** | ~first typed mutations | Narrow mutating ops with mandatory verification | Not started |
| **R8** | ~verification + completion | Close the loop for Boot Doctor cases | Not started |
| **R9** | ~Recovery CLI surface | Scriptable local interface over Core contracts | Not started |
| **R10** | ~Recovery Hub / packs spike | Host-side hub and Recovery Packs research only | Not started |
| **R11** | ~profile packaging | Clear WinPE vs future profiles; release naming | Not started |

## Parallel track (non-blocking)

| Track | Notes |
|-------|-------|
| Desktop-shell spike | Optional UX; e.g. Draft PR #12. May proceed independently of R1–R8. Must not block Recovery Core. |
| Gateway hardening | Continues as advisor-only improvements; never gains local authority. |

## Explicit non-goals for early slices

- Raw model command execution
- Collector-side mutation
- Analyzer-side execution
- Renaming existing executables in the same PR as contract introduction
- Treating experimental desktop shell as the release default

## Exit criteria for declaring Boot Doctor “available”

All must be true in code and docs:

1. Boot-specific evidence and findings are typed and tested.
2. Plans use typed operations only.
3. Any mutation has approval, backup (when applicable), verification, and audit.
4. Gateway remains optional and non-authoritative.
5. EffexorWinPE profile can run the vertical offline for the read path.
