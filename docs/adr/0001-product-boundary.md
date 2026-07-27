# ADR 0001: Product boundary — Effexor Recovery Platform

- Status: accepted (documentation)
- Date: 2026-07-27
- Supersedes naming ambiguity only; does not replace
  [`../decisions/0001-winpe-and-agent-gateway.md`](../decisions/0001-winpe-and-agent-gateway.md)

## Context

The repository is named EffexorWinPE and currently ships a WinPE diagnostics
MVP. Continuing to treat “WinPE image” as the entire product would block a
shared recovery core, additional surfaces (CLI/hub), and clear authority rules.

## Decision

Adopt **Effexor Recovery Platform** as the product name.

- **EffexorWinPE** is a boot/runtime **profile** of the platform.
- **Effexor Recovery Core** is the intended shared local engine.
- **Effexor Diagnostics**, **Effexor Recovery CLI**, **Effexor Recovery Gateway**,
  **Effexor Recovery Hub**, and **Recovery Packs** are named surfaces/components
  with distinct roles.
- Existing executables and schemas remain **legacy-compatible**; this ADR does
  not rename binaries or move Go packages.

## Consequences

- Docs and roadmap speak platform-first, profile-second.
- WinPE-specific work can proceed without claiming to be the whole architecture.
- Future contract PRs have a stable vocabulary.
- Readers must not assume Core/Hub/Packs/Boot Doctor already exist in code.
