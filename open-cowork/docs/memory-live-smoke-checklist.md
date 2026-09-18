# Memory Live Smoke Checklist

Manual companion to the deterministic memory smoke coverage in
`src/tests/memory/memory-smoke-harness.test.ts`. Run through these steps
against a real build before releases that touch the memory system.

## Cross-Workspace Recall

1. Start the app and open a session with workspace A (e.g. `/repo/workspace-a`).
2. Discuss a durable fact, e.g. "our gateway token rotates every 30 days".
3. Open a new session with a different workspace B.
4. Ask about the gateway token rotation.
5. Expected: the answer references the fact learned in workspace A and the
   prompt prefix contains an `<experience_memory>` block attributed to
   workspace A (`source=/repo/workspace-a`).

## Source Provenance

1. In the same cross-workspace session, open Settings → Memory.
2. Use the memory search/inspection views to locate the recalled entry.
3. Expected: the entry records its source workspace key and session so the
   analyst can trace where the memory came from.
4. Core memory entries appear under `<core_memory>` regardless of workspace.

## Non-Interactive Flows

1. Run the headless mode: `electron . --headless -p "..." --cwd /repo/workspace-a`.
2. Expected: memory ingestion still runs after the session completes and the
   next headless run in the same workspace recalls prior context.
3. Verify scheduled tasks (which run without the GUI) also ingest and recall
   memory for their configured working directory.

## Regression Signals

- Memory recall leaking across unrelated workspaces.
- Prompt prefix missing `<experience_memory>` / `<core_memory>` blocks.
- Memory writes failing silently when `userData` is read-only.
