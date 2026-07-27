# Effexor Recovery Platform — product definition

## One-line summary

Effexor Recovery Platform is a local-authority Windows recovery system.
EffexorWinPE is its primary boot/runtime profile today, not the whole product.

## Naming

| Name | Meaning |
|------|---------|
| Effexor Recovery Platform | Product umbrella |
| Effexor Recovery Core | Shared local recovery engine and contracts (target) |
| Effexor Diagnostics | Diagnostic UI / presentation surface |
| Effexor Recovery CLI | Scriptable local surface (target) |
| EffexorWinPE | WinPE image + onboard tools built by this repo |
| Effexor Recovery Gateway | Optional model-backed advisor backend |
| Effexor Recovery Hub | Future non-boot orchestration / lab surface |
| Recovery Packs | Future redistributable recovery content packs |

## What EffexorWinPE is

EffexorWinPE is:

- a reproducible WinPE build;
- a constrained Windows PE runtime for offline diagnostics;
- the current home of collector, agent client, and technician shell binaries.

EffexorWinPE is **not**:

- the long-term name of every surface;
- the owner of provider credentials;
- a place for unrestricted AI-driven mutation;
- synonymous with Effexor Recovery Platform.

## Primary recovery loop

The platform’s intended loop (target architecture; only Evidence → Finding
portions are substantially implemented today):

1. **Evidence** — collect typed, versioned observations.
2. **Finding** — interpret evidence with explicit confidence and limitations.
3. **Hypothesis** — propose plausible causes without inventing missing facts.
4. **Plan** — assemble typed steps with preconditions and expected effects.
5. **Approval** — technician confirms each mutating step locally.
6. **Backup** — capture rollback material before mutation when applicable.
7. **Operation** — execute a typed local operation under policy.
8. **Verification** — re-check evidence that the intended effect occurred.
9. **Rollback / Completion** — reverse on failure or close the case on success.

Gateway output may inform Finding / Hypothesis / Plan. It never grants Approval
and never executes Operation.

## First product vertical

**Boot Doctor** is the first planned product vertical: diagnose and (later)
guide repair of boot/BCD/offline Windows startup failures.

Boot Doctor is **not implemented** as a named product module yet. Current
collector and preflight capabilities are building blocks for it.

## Absolute prohibitions

- No raw model commands.
- Collector cannot mutate.
- Analyzer cannot execute.
- UI cannot bypass policy.
- Mutation without verification is incomplete.
- External gateway has no local authority.

## Compatibility stance

Current components (`effexorwinpe-*` executables, existing schemas, WinPE
payload layout) are **legacy-compatible**. Reframing does not schedule their
deletion. Future Core contracts should wrap or evolve them rather than force a
big-bang rename in this documentation PR.

## Related docs

- [Glossary](GLOSSARY.md)
- [Architecture overview v2](architecture/overview-v2.md)
- [Roadmap v2](roadmap-v2.md)
- [ADR 0001 — product boundary](adr/0001-product-boundary.md)
- [ADR 0002 — local authority](adr/0002-local-authority.md)
- [ADR 0003 — typed operations](adr/0003-typed-operations.md)
- [ADR 0004 — evidence before action](adr/0004-evidence-before-action.md)
- [ADR 0005 — desktop shell optional](adr/0005-desktop-shell-optional.md)
