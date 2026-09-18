# KIN Controlled Integration Recovery — Final Report (§20)

Session branch: `arena/01a0b669-cyber-kin` · Commit: `752a737`
Scope: repair the existing implementation, connect existing pieces, fix verified defects only, preserve OpenCowork, prove it works.

---

## A. What was broken (verified before fixing)

| # | Defect | Evidence | Status |
|---|--------|----------|--------|
| A1 | `cyberActionAuditTrail` TDZ — declared inside `app.whenReady` (L1410) but referenced at L1021 by the session-runtime extensions | static + crash on early tool call | **FIXED** |
| A2 | Renderer `ServerEvent` union missing 7 events the backend actually emits (`investigation.list/updated/event/plan/replan/replanRecommendation`, `subagent.progress`, `compaction.result`); `ClientEvent` missing 23 emitted client events; preload allowlist blocked `synthetic.*` | `npx tsc --noEmit` = 283 errors across 25 files | **FIXED** |
| A3 | Dropped event stream: `useIPC` had no cases for investigation.*, `subagent.progress`, `compaction.result` although the consumers (`SubagentTracker`, `ContextUsageBar`, workspace panels) already existed | static (dead consumers) | **FIXED** |
| A4 | Dead placeholder worker cwd: `entities.length > 0 ? undefined : undefined` — workers silently inherited the process working dir | static + runtime | **FIXED** (`getWorkspaceCwd`, fail-loud) |
| A5 | `applyHumanInterruption` accepted only the legacy batch shape; every UI payload carried `as any`; `suspicion`/`constraint`/`direction` kinds had no correct service mapping; `text.trim()` ran before validation | static + type errors | **FIXED** (normalize/validate, no `any`) |
| A6 | Store had zero investigation state; `App.tsx` mounted only the chat stack; selectors/hooks referenced by 5 workspace components did not exist | tsc cluster (a) + (b) | **FIXED** (store slice, selectors, view branch, Sidebar entry) |
| A7 | Synthetic scenario dual-type system: `scenarios/index.ts` imported a stale duplicate `scenario-types.ts` (`{id,description,run()}`) | 14 tsc errors | **FIXED** (repointed to canonical; stale file deleted) |
| A8 | `SyntheticEnvironmentService.load()` deadlock — `requireEnabled()` demanded an already-loaded store, so a fresh service could never `load()` (test suite had also never run: import depth `../src` vs `../../src`) | runtime repro in tests/integrations/synthetic-environment | **FIXED** |
| A9 | `ask` silently became `allow`: subagent permission resolver mapped everything non-`deny` to `allow`; GUI cyber capabilities used the subagent resolver | static (index.ts resolver) | **FIXED** (fail-closed subagent/headless; interactive prompt for GUI) |
| A10 | Credential redactor destroyed ordinary English (`accessing`, `Authorization`, `Infrastructure` → `[redacted]`) and double-wrapped `[[redacted]]` | runtime repro (tsx) | **FIXED** |
| A11 | `cyber_capability_execute` read `ctx.sessionId`, but the real pi `ExtensionContext` carries `sessionManager.getSessionId()` — tool dead at runtime | static + contract in node_modules types | **FIXED** |
| A12 | Unbounded `walkFiles` (no depth/count/symlink limits) and uncontained filesystem capability paths | static | **FIXED** (bounded + contained, configurable, fail-closed) |
| A13 | `investigation.replan` result never broadcast; `redirectTask` forwarded arbitrary renderer-supplied role strings | static | **FIXED** |
| A14 | hmpx-kernel didn't import the types it references; probe executor typed on the unmapped capability; `UNKNOWN` findings violated the evidence type | 22 tsc errors | **FIXED** (compile-only; still unwired by design) |

## B. What changed (commit `752a737`)

- **Types/contract**: `src/renderer/types/index.ts` (full Client/ServerEvent unions), `src/preload/index.ts` (typed `synthetic` namespace + allowlist), `src/main/client-event-utils.ts`, `src/shared/cyber/investigation-types.ts` (`HumanInterruptionKind` incl. `direction`, `ApplyHumanInterruptionInput`, `plannedTaskId`).
- **Store/UI**: `store/index.ts` (investigations slice + `activeView`), `store/selectors.ts` (5 hooks), `hooks/useIPC.ts` (8 forwarded event cases), `App.tsx` (lazy Investigations view), `Sidebar.tsx` (nav entry), `InvestigationWorkspace.tsx` (list view, plan/recommendation loading, hooks-order fix, `as any` removed), `InvestigationsList.tsx` + `InvestigationHeader.tsx` + new `demo-label.tsx` (DEMO badge).
- **Main**: `index.ts` (audit-trail TDZ, replan broadcast, role validation, resolvers, orchestrator cwd), `runtime-investigation-orchestrator.ts` (payload normalizer/validator, workspace cwd, role list), `parallel-investigation-engine.ts` (exported `INVESTIGATION_AGENT_ROLES`), `cyber-capability-registry.ts` (containment + bounded walk), `cyber-capability-extension.ts` (real ctx session id, workspace anchor), `cyber-permission-policy.ts` (dead branch removed), `integration-credentials.ts` (redaction false-positives), `synthetic-environment-service.ts` (load deadlock), `utils/logger.ts` (16-hex trace ids), `db/database.ts` (injectable db path).
- **Tests**: golden-path integration test (new), containment/walk-bound regression specs, CLOSED-GAP conversions of 14 stale DOCUMENTS-GAP specs (implementation had already hardened; verified at runtime first), extension-test ctx stubs aligned to the real pi contract, synthetic-environment import depth.
- **Docs**: `docs/memory-live-smoke-checklist.md` restored (was swallowed by the `docs/` gitignore rule; a test requires it) + `docs/` un-ignored.

## C. What works now (proven, not claimed)

1. **Typed IPC end-to-end** — renderer events = backend emissions; preload allowlist complete; `npx tsc --noEmit` = **0 errors** (was 283).
2. **Golden path against the real backend** — `tests/investigation-golden-path.test.ts` drives create → plan → human interruption (batch + all UI kinds) → human-directed task → replan → report over real better-sqlite3 (in-memory) through the same orchestrator/service the IPC handlers call. No mocked success.
3. **Event stream** — investigation.*, subagent progress, and compaction events now reach the renderer consumers; per-session compaction history records manual vs auto.
4. **Security in executable code** — filesystem containment (rejects `/etc/passwd`, traversal encodings, unresolvable containment = refuse), bounded walk (depth ≤ 12 / files ≤ 2000 hard caps, symlinks never followed), `ask` → real interactive permission prompt in GUI sessions (60 s timeout → deny), `ask` → deny for subagents/headless, capability classifier fails closed (unmatched → HIGH_RISK_ACTION), audit records deep-frozen, list() deep-cloned, denied+executed actions audited and mirrored into the investigation timeline.
5. **DEMO separation** — synthetic environment is flag-gated (`CYBER_SYNTHETIC_ENABLED=1`), seeds investigations watermarked `[SYNTHETIC DEMO]` with demo-only notes/constraints/timeline events, and the workspace UI renders a DEMO badge (list + header) via `isSyntheticDemoInvestigation()`.
6. **Redaction** — 13/13 redaction specs pass including short AWS keys, Slack tokens, Basic-auth, generic payload/body/data keys; English words survive.
7. **Builds** — `vite build` (renderer + preload) ✓, `build:wsl-agent` / `build:lima-agent` (tsc) ✓, MCP bundle ✓, `eslint` **0 errors** (10 pre-existing warnings).

## D. What remains incomplete (truthful)

- **Live worker execution is UNVERIFIED end-to-end**: the orchestrator → SessionManager → pi-agent wiring exists (session create with workspace cwd, allowed tools, abort, session linking, structured-output parsing — all covered by unit tests), but a real worker run needs a configured model/API key, which this sandbox does not have. Nothing here fakes it.
- **Electron GUI runtime** (window, real clicks) was not exercised in this sandbox; renderer verification is typecheck + build + component-level tests. The investigations view mounts through the same PanelErrorBoundary/Suspense path as ChatView.
- **Durability of the audit trail**: records are deep-frozen in memory and mirrored into the persisted investigation event log, but there is no standalone append-only file, hash chain, or MAC. (Known, documented limitation — one test pins it.)
- **Task control with running workers** (pause/resume/cancel/reprioritize against live execution) is wired to `ParallelTaskManager` and reaches the scheduler/abort controllers; pre-execution calls are verified no-ops. Verifying mid-flight cancellation requires live workers (same API-key constraint as above).
- **electron-builder packaging** was not run (downloads Electron binaries; sandbox blocks the network endpoint). Compile/bundle stages all pass.

## E. Tests — exact commands and real results

| Command | Result |
|---|---|
| `npx tsc --noEmit` | **0 errors** (baseline before recovery: 283 errors / 25 files) |
| `npx vitest run` | **1389 passed / 5 failed** of 1394 (190 files) — baseline was 1348/28 |
| `npm run lint` | **0 errors**, 10 warnings (pre-existing hook-deps/unused-var warnings) |
| `npx vite build` | success (renderer 7.97 s + preload 27 ms) |
| `npm run build:wsl-agent` / `build:lima-agent` | success |
| `node scripts/bundle-mcp.js` | success ("All MCP servers built successfully!") |

Classification of the 5 remaining test failures:

- **5 × incorrect expectation / obsolete (FUTURE)**: `dark-theme-palette.test.ts` (2), `welcome-view-claude-layout.test.ts` (2), `chat-view-claude-layout.test.ts` (1). These assert literal source strings (`--color-background: #171614`, `rounded-[1.9rem]`, "Open Cowork" eyebrow copy) for a cosmetic redesign that was never implemented. Per the no-redesign constraint the redesign was intentionally not built; the specs are the design's executable spec, kept as FUTURE work. Not deleted.
- **0 × environment flake**: the former `recent-workspace-files` clock-jitter failures were fixed with deterministic `utimes` stamps — the file now passes 5/5 repeat runs and the full suite is flake-free.
- **0 × new regression**: every failure introduced by a recovery change (orchestrator cwd, containment, ctx stubs, trace-id width, registry widening) was fixed in the same phase — final suite contains no regressions from this work.

## F. Security posture (executable controls)

| Control | Enforcement point | Verified by |
|---|---|---|
| Path containment (normalize→resolve→contain→reject) | `CyberCapabilityRegistry.enforceFilesystemContainment` via `isPathWithinRoot` (decodes `%00`, `%2e%2e`, double-encoding before segment resolution) **plus real-path verification**: the deepest existing ancestor is `realpath`-resolved and re-checked, so symlink chains escaping the workspace are refused | `tests/security-path-traversal.test.ts` 18/18, registry specs incl. symlink-escape |
| Fail-closed without workspace | registry refuses filesystem capabilities when no `workspacePath` | new registry spec |
| Bounded directory walk | `walkFiles(dir, limits)` — configurable `maxDepth`/`maxFiles`, hard caps 12/2000, symlinks skipped | implementation + caps clamp unit |
| Capability approval chain | exists → risk-level allowlist → investigation link → permission rules (`allow`/`deny`/`ask`) → interactive prompt on `ask` → policy (`HIGH`/`DESTRUCTIVE` need explicit approval) → execute → audit | extension specs + policy specs |
| `ask` never silently `allow` | GUI: `SessionManager.requestPermission` (60 s → deny); subagent/headless: `ask` → deny | code + resolver semantics |
| Classifier fail-closed default | unmatched capability → `HIGH_RISK_ACTION` → approval required | `tests/security-capability-classifier.test.ts` 8/8 |
| Audit immutability | deep freeze at append, deep-clone on read, denied actions recorded, records mirrored to investigation events | `tests/security-audit-trail.test.ts` 9/9 |
| Credential redaction | string/object/error redaction incl. scheme tokens, generic keys; no false-positive on English | `tests/security-credential-redaction.test.ts` 13/13 |

Remaining security gaps (documented, not hidden): audit trail has no hash chain/MAC or append-only durable file; subagent tool allow/deny still relies on the shared rules store (no per-subagent identity); containment is lexical (symlinked paths inside the workspace are skipped by the walker but `inspect_file`/`calculate_hash` will `stat`/read through a symlink if an agent names one directly — flagged as a MEDIUM blocker below).

## G. Product reality matrix (17 capabilities)

| # | Capability | Reality | Basis |
|---|-----------|---------|-------|
| 1 | Investigation create/list/open/archive | **YES** | golden-path test over real sqlite; typed IPC handlers |
| 2 | AI planning (role-based plan) | **YES** | real `InvestigationPlanner` in golden-path test |
| 3 | Replan + recommendation approval | **YES** backend / **PARTIAL** UI (approve→`investigation.replan` wired; prompt flow unverified in Electron) | golden-path test + code |
| 4 | Human interruption (all UI kinds) | **YES** | golden-path test covers directive/note/suspicion/constraint/hypothesis/promote/reject/risk |
| 5 | Human-directed task creation | **YES** | golden-path test |
| 6 | Task pause/resume/cancel/reprioritize | **PARTIAL** — reaches `ParallelTaskManager`/abort controllers; mid-flight with live workers unverified | unit tests + code |
| 7 | Parallel worker execution (LLM) | **UNVERIFIED** — needs model/API key; wiring unit-tested | honest gap |
| 8 | Evidence/hypotheses/timeline persistence | **YES** | service + real-DB tests |
| 9 | Workspace UI (board, feed, graph, panels) | **PARTIAL** — compiles, typed, store-wired; not exercised in a running Electron window | tsc/build/component tests |
| 10 | Report generation/export | **YES** generate/markdown (tested); **PARTIAL** save-dialog export | golden-path test |
| 11 | Local cyber capabilities (11 executors) | **YES** with containment + bounds | registry specs |
| 12 | Permission system (rules + prompts) | **YES** for the cyber path; rules store itself is pre-existing OpenCowork | extension specs |
| 13 | Cyber audit trail | **YES** in-memory + event-log mirror; **NO** durable hash-chained log (documented) | audit specs |
| 14 | Credential redaction | **YES** | 13/13 |
| 15 | Synthetic DEMO environment | **YES** — flag-gated, watermarked, DEMO-badged in UI, separated from real findings | 13/13 service tests + demo-label |
| 16 | HMPX meta-brain kernel | **NO in product path** — compiles (was 22 errors), tests pass, deliberately unwired per scope | tsc + hmpx specs |
| 17 | Vendor adapters / IntegrationRegistry | **PARTIAL** — bridge + fallback logic tested with fake adapters; no real vendor credentials; unwired in V1 | bridge specs |

## H. Beta blockers

**CRITICAL**
- C1. Live worker execution unverified (needs one environment with a configured model + API key; run `investigation.execute` once and confirm worker sessions complete and evidence lands). Everything up to dispatch is tested.

**HIGH**
- H1. Electron GUI smoke pass: open the Investigations view, create → execute → approve replan with a real window (component/store layers are verified; the running app is not). Environmental evidence for why this sandbox cannot close it: the Electron binary itself cannot be installed — `npm ci --ignore-scripts` skips its postinstall, and the postinstall download fails because release assets redirect to `objects.githubusercontent.com`, which is unreachable from this sandbox (`curl` to the 302 target fails; `npmmirror.com` mirror unreachable; direct download via `node install.js` fails with `Client network socket disconnected before secure TLS connection was established`). The app's own headless RPC mode (`electron . --headless --mode rpc --cwd …`, which serves `handleClientEvent` over stdin JSONL and would have driven the same IPC path as the GUI without a display) was the intended vehicle and is blocked by the same missing binary.

**MEDIUM**
- M1. Durable append-only audit file (+ optional hash chain) — currently memory + investigation event mirror only.
- M2. Mid-flight task-control verification once C1 is closed (pause/cancel a running worker and confirm abort + event trail).
- M3. 10 pre-existing eslint warnings (hook-deps in `WorkerInspector`/`useApiConfigState`, unused `_` in store).

*(Fixed during recovery: the former H2 — symlink read-through — capability inputs are now real-path resolved through their deepest existing ancestor and refused when they escape the workspace; and the former M3 — the `recent-workspace-files` clock-jitter flake — now uses deterministic `utimes` stamps, stable 5/5 across repeat runs.)*

**FUTURE**
- F1. The 5 UI-redesign specs (charcoal palette, warm orange accent, editorial welcome/header layouts) — intentional design debt, specs preserved.
- F2. HMPX kernel, IntegrationRegistry/vendor adapters, synthetic-as-source-investigations: compiled and tested, deliberately unwired in V1 golden path.
- F3. Chat↔investigation deep links (open a session's linked investigation from the chat header).

**Not beta-ready on compile alone** — compile is green (tsc 0, lint 0 errors, build ✓), the golden path is proven over the real backend, and the security controls are executable; the remaining beta gate is C1 + H1 in a model-configured environment.
