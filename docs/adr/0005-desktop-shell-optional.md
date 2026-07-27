# ADR 0005: Desktop shell is optional

- Status: accepted (documentation)
- Date: 2026-07-27

## Context

A Windows-like desktop inside WinPE may improve technician UX (taskbar, windowed
Diagnostics, file manager). A parallel experimental track (for example Draft
PR #12 on `feature/winpe-desktop-shell-spike`) explores that path.

Desktop shell work is easy to mistake for the product core. It must not delay
Recovery Core contracts or Boot Doctor design.

## Decision

- Desktop shell is an **optional parallel UX track**.
- Default / release profile remains the minimal shell path until a separate
  decision graduates desktop shell.
- Recovery Core, Diagnostics contracts, and Boot Doctor planning proceed
  **independently** of desktop-shell spike status.
- PR #12 (or successors) must not be treated as a merge gate for Core work.
- Desktop shell must not redesign Effexor Diagnostics appearance as a
  prerequisite for platform reframing.

## Consequences

- Roadmap v2 lists desktop shell as non-blocking.
- Core PRs do not wait on WinXShell provenance, ISO spike metrics, or Ventoy
  desktop smoke.
- If desktop shell is later adopted, it hosts Diagnostics; it does not become
  the authority plane.
