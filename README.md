# AegisAI_v2

## Start Here

This repository is organized around an agent-first MVP baseline for AegisAI.

- Agents should start with [`AGENTS.md`](./AGENTS.md).
- The canonical execution path lives in [`specs/001-aegisai-mvp-foundation/quickstart.md`](./specs/001-aegisai-mvp-foundation/quickstart.md).
- The background product baseline lives in [`spec 2.2.md`](./spec%202.2.md).
- The active implementation package lives in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/).

If you are starting development work, follow the agent path `AGENTS.md -> quickstart.md ->
feature package` instead of jumping directly to `tasks.md`.

## GitHub Conventions

The repository follows the GitHub workflow convention documented in
[`docs/github-conventions.md`](./docs/github-conventions.md).

- Branches use `feat/<issue-number>-<short-feature>` and the matching `fix/`,
  `refactor/`, `release/`, and `hotfix/` variants
- Commit messages use `<type>: <description>`
- Issue titles and PR titles must match
- `dev` is the default integration branch and `main` remains the release-ready branch

Spec Kit feature docs still live in [`specs/001-aegisai-mvp-foundation/`](./specs/001-aegisai-mvp-foundation/),
so GitHub-style working branches may still need `SPECIFY_FEATURE` when running Spec Kit
helpers.

## CI

GitHub Actions runs the same baseline verification path used locally:

- `corepack pnpm lint`
- `corepack pnpm test`
- `corepack pnpm typecheck`
- `corepack pnpm build`
