# Glossary

Terms below are product language for Effexor Recovery Platform. Where an older
EffexorWinPE name still appears in code or schemas, that name remains valid.

| Term | Definition |
|------|------------|
| **Effexor Recovery Platform** | The overall product: local recovery across profiles and surfaces. |
| **Effexor Recovery Core** | Target shared local engine for evidence, findings, plans, policy, operations, and verification. Not a separate shipped package yet. |
| **Effexor Diagnostics** | Technician-facing diagnostics presentation. Today this is primarily the Win32 shell in WinPE. |
| **Effexor Recovery CLI** | Target command-line surface over the same local contracts. Not shipped as a distinct product binary yet. |
| **EffexorWinPE** | WinPE boot/runtime profile and media produced by this repository. |
| **Effexor Recovery Gateway** | Optional authenticated backend for model-backed reasoning. Advises only; has no local authority. |
| **Effexor Recovery Hub** | Future host/lab orchestration surface. Not implemented. |
| **Recovery Packs** | Future packaged recovery content / tool bundles. Not implemented. |
| **Evidence** | Typed observed facts recorded in versioned reports/contracts. |
| **Finding** | Interpreted conclusion grounded in evidence, with confidence and limits. |
| **Hypothesis** | Candidate explanation that remains provisional until verified. |
| **Plan** | Ordered set of typed steps with preconditions and expected outcomes. |
| **Approval** | Explicit local technician confirmation required before mutation. |
| **Backup** | Rollback material captured before a mutating operation when applicable. |
| **Operation** | Typed local action permitted by policy (read-only today; mutations are future). |
| **Verification** | Post-operation evidence check that the intended effect occurred. |
| **Rollback / Completion** | Either reverse a failed mutation path or close a successful recovery case. |
| **Boot Doctor** | First planned product vertical for boot/startup recovery. Not implemented as a named module yet. |
| **Local authority** | Only on-device policy and technician approval may authorize execution. |
| **Desktop shell (optional)** | Parallel UX track that may host Diagnostics inside a WinPE desktop environment. Experimental; must not block Core. |
| **Legacy-compatible** | Existing executables, scripts, and schemas remain supported while platform language evolves. |
