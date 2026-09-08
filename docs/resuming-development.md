# Resuming development from the correct checkout

Project progress must be reported against an identified commit and integration branch.
A local worktree can remain on an already merged branch while `dev` advances through
several milestones. Its task list and passing tests prove only the local snapshot.

## Reconcile before selecting work

Read the local `AGENTS.md` and its canonical quickstart first. Then inspect the repository:

```powershell
git rev-parse --show-toplevel
git status --short
git branch --show-current
git remote -v
git fetch origin
git rev-parse HEAD
git rev-parse origin/dev
git log -5 --oneline origin/dev
git log --oneline HEAD..origin/dev
git log --oneline origin/dev..HEAD
git show origin/dev:AGENTS.md
gh pr status
gh issue list --state open
```

If fetch or GitHub access fails, state that remote freshness is unverified; do not present
cached refs as current. If working detached, record the commit explicitly. Inspect the
body, state, base, head, and checks of the relevant PR, then read its linked issue. A
merged PR remains history, even when a local branch with the same name still exists.

If the active package differs, read the quickstart named by `origin/dev:AGENTS.md` before
selecting the next task. Follow that package's read order in the checkout selected for
the new work. Intentional maintenance of an older release must be named explicitly.

## Preserve local work

Do not discard, automatically stash, overwrite, or mass-stage a dirty checkout to bring
it up to date. Leave its tracked and untracked changes in place. Inspect
`git worktree list`, create or select the issue, and use a new issue-named branch/worktree
based on the verified `origin/dev` for integration work. The original checkout remains
available for the user's demo or unfinished work.

Compare relevant local changes with the new baseline before porting them. A local fix
may already exist in a different implementation on `dev`. Port only a reviewed missing
change and validate it against the new contracts. Tests from the original worktree are
not validation of the new branch.

## Report and publish against the same branch

Record the working path, branch, base commit, active feature, linked issue/PR, completed
scope, remaining blockers, and checks actually run. Keep issue and PR titles identical
and use the repository templates. Publish reviewed changes to a Draft PR targeting `dev`;
do not reuse a merged PR or claim that local changes have been pushed before verifying
the remote head.

Distinguish implementation completion, repository validation, CI success, merge, and
external execution. Update the issue checklist and PR body when scope or validation
changes. Leave external requirements open and link their evidence or preparation issue.

## Reconciliation checkpoint on 2026-09-08

The retained `feat/127-scan-plane-mock-pipeline` checkout was at `a8e51eb` with local
changes and the 002 baseline. Its PR [#128](https://github.com/AigisAI/AegisAI_v2/pull/128)
had already merged. Integration commit `3154e31` from
[PR #315](https://github.com/AigisAI/AegisAI_v2/pull/315) uses the 006 baseline and binds
005 deployment preflight to a signed T056 `GO`.

This is a dated reconciliation record, not a permanently current commit. Fetch and
compare again on every resumption. The outstanding operational work is tracked in
[issue #317](https://github.com/AigisAI/AegisAI_v2/issues/317) and the
[T053 handoff](./operations/t053-qualification-handoff.md).
