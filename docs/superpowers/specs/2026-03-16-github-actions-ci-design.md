# GitHub Actions CI Bootstrap Design

**Issue**: `#20`
**Title**: `Feat: Github Actions CI 초기설정`
**Date**: `2026-03-16`

## Goal

Add a baseline GitHub Actions CI workflow that validates the workspace on pull requests and pushes before any deployment automation is introduced.

## Scope

- Create `.github/workflows/ci.yml`
- Run the repository verification path on GitHub-hosted runners
- Cover install, lint, test, typecheck, and build for the pnpm workspace
- Use deterministic Node and pnpm setup with dependency caching

## Design Choices

1. Keep CI as a single workflow with one verification job because the repository is still small and the current command set is already centralized in the root package scripts.
2. Include `build` from day one because the workspace build already passes locally and catches integration errors that lint/test/typecheck can miss.
3. Leave Docker image build/push and deployment orchestration out of this issue so `#21` can own CD concerns cleanly.
4. Add a lightweight repository test that asserts the workflow file contains the expected triggers and commands, so future edits to CI have a local regression check.

## Non-Goals

- No Docker image build or registry push
- No environment-specific deployment logic
- No secrets or release automation

## Validation

- The workflow structure test passes locally
- Workspace `lint`, `test`, `typecheck`, and `build` still pass locally
