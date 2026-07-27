# Effexor Recovery Platform

Effexor Recovery Platform is the product name for a technician-focused Windows
recovery system. **EffexorWinPE is one boot/runtime profile of that platform**,
not the entire product.

This repository currently implements a WinPE-centered diagnostics MVP under the
historical name EffexorWinPE. The documents in this PR reframe that work as the
foundation of a wider recovery platform without changing runtime behavior.

## Product names

| Name | Role |
|------|------|
| **Effexor Recovery Platform** | Overall product: local-authority recovery across boot profiles and surfaces |
| **Effexor Recovery Core** | Shared local engine: evidence, findings, plans, policy, typed operations, verification |
| **Effexor Diagnostics** | Technician-facing diagnostic presentation (today: Win32 shell in WinPE) |
| **Effexor Recovery CLI** | Command-line / scripting surface for the same local contracts |
| **EffexorWinPE** | WinPE boot media and runtime profile built from this repository |
| **Effexor Recovery Gateway** | Optional authenticated backend for model-backed reasoning (no local authority) |
| **Effexor Recovery Hub** | Future host-side / lab-side orchestration surface (not implemented) |
| **Recovery Packs** | Future packaged recovery content and tool bundles (not implemented) |

## Current implemented functionality

Honest inventory of what this repository already ships today:

- reproducible WinPE build scripts and image payload allowlist;
- dependency-free Go diagnostic collector (`effexorwinpe-collector`);
- versioned JSON diagnostic report contract (`diagnostic-report` 1.3.0);
- read-only hardware, storage reliability/SMART counters, BitLocker availability,
  firmware, BCD, and offline Windows inventory;
- offline evidence-backed diagnostic preflight with confidence, follow-up
  questions, limitations, and typed **read-only** next steps
  (`effexorwinpe-agent`);
- resumable diagnostic sessions with symptoms, answers, and a compact audit
  timeline;
- optional HTTPS client to the model-backed gateway, with removable device token
  and separate upload approval;
- authenticated asynchronous gateway with strict model output, official-domain
  web retrieval, source capture, and a **read-only** operation boundary
  (`effexorwinpe-gateway`);
- Win32 technician GUI shell (`effexorwinpe-shell`) for inspection and export;
- payload/driver manifests, safety rules, and CI.

Existing executables and package paths remain legacy-compatible names. They are
**not** deprecated-to-delete; they are current implementations that future Core
contracts must remain compatible with.

## Current experimental functionality

- Experimental WinPE desktop-shell spike (optional UX track; see parallel work
  such as Draft PR #12). It must not block Recovery Core design.
- Local-only third-party shell staging, when present, remains experimental and
  redistribution-gated.

## Target architecture

See:

- [`docs/PRODUCT.md`](docs/PRODUCT.md)
- [`docs/architecture/overview-v2.md`](docs/architecture/overview-v2.md)
- [`docs/architecture/recovery-contracts.md`](docs/architecture/recovery-contracts.md)
- [`docs/roadmap-v2.md`](docs/roadmap-v2.md)
- ADRs under [`docs/adr/`](docs/adr/)

Target direction in one sentence: local Recovery Core owns authority; WinPE is
a profile; the gateway advises; mutation is typed, approved, backed up,
verified, and never driven by raw model commands.

## Not implemented yet

Do **not** treat these as shipped:

- Effexor Recovery Core as a separate package boundary;
- typed mutation operations / recovery coordinator;
- case store / work-order hub;
- Boot Doctor product vertical (planned first vertical only);
- Effexor Recovery Hub;
- Recovery Packs;
- Effexor Recovery CLI as a distinct product surface;
- guaranteed desktop-shell UX in release images.

## Repository layout

```text
build/                      Windows build and validation scripts
cmd/effexorwinpe-collector/ WinPE diagnostic collector executable
cmd/effexorwinpe-agent/     Offline preflight, session, and gateway client
cmd/effexorwinpe-gateway/   Server-side authenticated model gateway
cmd/effexorwinpe-shell/     Technician GUI shell
contracts/                  Versioned API and report schemas
deploy/gateway/             Container and deployment example; no secrets
docs/                       Product, architecture, roadmap, and decisions
drivers/                    Documentation and local driver staging area
internal/                   Collector, triage, shell, and gateway code
manifests/                  Auditable image contents
payload/EffexorWinPE/       Files copied into X:\EffexorWinPE in WinPE
```

The image payload is copied from the closed allowlist in
`manifests/image-payload.json`. Files merely present under `payload/EffexorWinPE`
are never included automatically.

## Diagnostic session and agent

The automatic boot flow creates `initial-diagnosis-session.json` beside the
initial assessment. Resume it from the WinPE command prompt to add context:

```powershell
X:\EffexorWinPE\bin\effexorwinpe-agent.exe `
  --input X:\EffexorWinPE\reports\initial.json `
  --output X:\EffexorWinPE\reports\initial-diagnosis.json `
  --session X:\EffexorWinPE\reports\initial-diagnosis-session.json `
  --interactive
```

Online submission is disabled unless the technician supplies an HTTPS gateway
URL, an external token file, and `--approve-upload` together. See
[`docs/gateway.md`](docs/gateway.md).

## Build prerequisites

On a Windows 11 x64 build machine install:

1. Windows ADK (Deployment Tools) from the
   [official Microsoft download page](https://learn.microsoft.com/windows-hardware/get-started/adk-install).
2. The matching Windows PE add-on for that ADK.
3. Go 1.24 or newer.
4. PowerShell 7 recommended; Windows PowerShell 5.1 is sufficient for the initial scripts.

Start **Deployment and Imaging Tools Environment** as administrator, then launch
`powershell` (or `pwsh`) from that window. From the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build\Test-Repository.ps1
.\build\Build-WinPE.ps1
```

Default ISO output: `out/EffexorWinPE-amd64.iso`.

## Safety model

Absolute rules for the platform (current and future):

1. No raw model commands.
2. Collector cannot mutate.
3. Analyzer cannot execute.
4. UI cannot bypass policy.
5. Mutation without verification is incomplete.
6. External gateway has no local authority.

Inspection remains the default. Any future mutating repair must be explicit,
previewable, and confirmed by the technician. See
[`docs/adr/0002-local-authority.md`](docs/adr/0002-local-authority.md) and
[`docs/adr/0004-evidence-before-action.md`](docs/adr/0004-evidence-before-action.md).

## Licensing

First-party source code is published under the MIT License; see `LICENSE`. That
license does not grant redistribution rights for Microsoft components, Windows
images, drivers, or third-party utilities.
