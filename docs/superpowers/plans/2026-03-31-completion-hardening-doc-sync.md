# Completion Hardening And Documentation Sync Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sync the canonical repository docs and completion gates with the MVP code that has already shipped.

**Architecture:** This work stays documentation-first. Add a single hardening review artifact in the active feature package, then realign the repository entrypoint docs and task list to that artifact and the shipped file boundaries. Finish by adding a lightweight regression test that reads the canonical docs and protects the completion path from drifting again.

**Tech Stack:** Markdown documentation, Jest/Nest test harness, Node filesystem reads

---

### Task 1: Add Completion Hardening Artifacts

**Files:**
- Create: `specs/001-aegisai-mvp-foundation/hardening-review.md`
- Modify: `docs/superpowers/specs/2026-03-31-completion-hardening-doc-sync-design.md`
- Modify: `docs/superpowers/plans/2026-03-31-completion-hardening-doc-sync.md`

- [ ] **Step 1: Write the hardening review content**

Document the shipped behavior for sessions, CSRF, throttling, health, report expiry, queue recovery, provider errors, and frontend error states.

- [ ] **Step 2: Confirm the hardening review points at real code paths**

Check referenced backend/frontend files and existing regression tests before finalizing the markdown.

### Task 2: Sync Canonical Entry Docs

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `specs/001-aegisai-mvp-foundation/quickstart.md`
- Modify: `specs/001-aegisai-mvp-foundation/tasks.md`

- [ ] **Step 1: Update entrypoint docs**

Keep `README.md`, `AGENTS.md`, and `quickstart.md` aligned on the same start path, completion gate, and validation commands.

- [ ] **Step 2: Update stale task descriptions and statuses**

Rewrite report/dashboard task file paths so they match the actual implementation, then mark the completed tasks accordingly.

### Task 3: Add Completion Regression Coverage

**Files:**
- Create: `apps/api/test/docs/completion-docs.e2e-spec.ts`

- [ ] **Step 1: Write the failing docs regression test**

Assert that the canonical docs mention the final validation commands, hardening review artifact, and completed task states.

- [ ] **Step 2: Run the targeted docs test**

Run the new spec in isolation and confirm it passes after the documentation changes.

### Task 4: Run Final Validation

**Files:**
- Modify: none

- [ ] **Step 1: Run repository validation**

Run:

```powershell
corepack pnpm lint
corepack pnpm test
corepack pnpm typecheck
corepack pnpm build
```

- [ ] **Step 2: Commit once validation is green**

Use a `chore:` commit message that reflects completion doc sync and hardening gate alignment.
