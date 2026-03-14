# GitHub Convention Alignment Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align repository docs and Spec Kit PowerShell helpers with the team's GitHub branching, commit, and PR conventions without breaking the existing MVP spec directory flow.

**Architecture:** Treat the GitHub convention as the new source of truth for day-to-day branch and PR operations while preserving `specs/001-aegisai-mvp-foundation` as the active implementation package. Update docs to state the rules clearly, then adjust Spec Kit scripts so GitHub-style branches work by default and `SPECIFY_FEATURE` remains the bridge to the active spec directory.

**Tech Stack:** Markdown, PowerShell, Git, Spec Kit helper scripts

---

## Chunk 1: Documentation Source Of Truth

### Task 1: Publish the repository GitHub workflow convention

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `.github/PULL_REQUEST_TEMPLATE.md`

- [ ] **Step 1: Write the failing verification criteria**

Record the expected rules before editing:
- Branches follow `feat/<issue-number>-<short-feature>` and related `fix/`, `refactor/`, `release/`, `hotfix/` forms.
- Commit messages follow `<type>: <description>`.
- Issue and PR titles match.
- PR template explicitly asks for branch/issue and CI confirmation.

- [ ] **Step 2: Implement the minimal documentation updates**

Add a concise convention section to the repository entry docs and update the PR template wording so contributors can follow the new workflow without relying on tribal knowledge.

- [ ] **Step 3: Verify the docs mention the new rules**

Run: `rg -n "feat/|Git-flow|GitHub-flow|<type>: <description>|이슈와 PR 제목|SPECIFY_FEATURE" README.md AGENTS.md .github/PULL_REQUEST_TEMPLATE.md`
Expected: matches show the GitHub convention in the selected docs.

## Chunk 2: Spec Kit Script Compatibility

### Task 2: Make PowerShell helpers accept GitHub-style branches

**Files:**
- Modify: `.specify/scripts/powershell/common.ps1`
- Modify: `.specify/scripts/powershell/check-prerequisites.ps1`
- Modify: `.specify/scripts/powershell/setup-plan.ps1`
- Modify: `.specify/scripts/powershell/create-new-feature.ps1`

- [ ] **Step 1: Define the failing behavior**

Confirm the current helper rejects `feat/<issue>-<name>` branches because it only accepts `001-feature-name`.

- [ ] **Step 2: Implement the minimal compatibility layer**

Update shared branch validation and feature path resolution so:
- GitHub convention branches are valid.
- `main` and `dev` remain valid base branches.
- The active spec directory still resolves through `SPECIFY_FEATURE` or the existing baseline feature when the branch name is not a spec directory.

- [ ] **Step 3: Verify script outputs**

Run targeted PowerShell commands that exercise:
- branch validation on the current `feat/13-workspace-bootstrap` branch
- path resolution through the active feature package

Expected: no feature-branch validation failure and the returned feature paths still point at `specs/001-aegisai-mvp-foundation`.

## Chunk 3: Final Verification

### Task 3: Re-run repository checks and capture the next starting point

**Files:**
- Modify: `docs/handoffs/2026-03-14-phase-1-bootstrap-handoff.md`

- [ ] **Step 1: Refresh any handoff wording affected by the convention update**

Keep the handoff aligned with the new branch convention and active feature guidance.

- [ ] **Step 2: Run verification**

Run:
- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `powershell -ExecutionPolicy Bypass -File .specify/scripts/powershell/check-prerequisites.ps1 -PathsOnly`

Expected: workspace checks pass and prerequisite output resolves the active feature paths.

- [ ] **Step 3: Prepare the completion summary**

Summarize the new source-of-truth docs, the Spec Kit compatibility behavior, and any residual caveats for the user.
