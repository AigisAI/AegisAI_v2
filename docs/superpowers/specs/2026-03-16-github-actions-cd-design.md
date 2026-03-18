# GitHub Actions CD Deploy Design

**Issue**: `#21`
**Title**: `Feat: Github Actions CD 배포 설정`
**Date**: `2026-03-16`

## Goal

Add a production deployment pipeline that builds Docker images in GitHub Actions, publishes them to GHCR, and deploys the latest main branch release to a single Oracle Cloud VPS over SSH.

## Scope

- Add production Dockerfiles for the API and web apps
- Add a production Docker Compose stack for Oracle Cloud VPS deployment
- Add a GitHub Actions CD workflow for build, push, and remote deploy
- Document the required VPS files and GitHub secrets for deployment

## Design Choices

1. Use GHCR as the container registry because it integrates cleanly with GitHub Actions and avoids adding a second external registry before the MVP ships.
2. Target a single Oracle Cloud Compute VPS with Docker Compose because the user explicitly chose VPS hosting and the MVP does not need orchestration beyond one host yet.
3. Deploy only on `main` pushes and manual dispatch so `dev` remains a safe integration branch while production releases stay explicit.
4. Keep application runtime secrets on the server-side `.env` file instead of rewriting them from GitHub Actions each deploy.
5. Add repository regression tests for the CD workflow and deploy files so future edits can be validated locally even without Docker installed.

## Non-Goals

- No Kubernetes, ECS, or multi-host orchestration
- No blue-green or canary rollout logic
- No automatic database migration execution on deploy
- No staging environment in this issue

## Validation

- CD config regression tests pass locally
- Workspace `lint`, `test`, `typecheck`, and `build` still pass
- Docker image builds are validated by GitHub Actions after the PR runs because Docker is not available in this local environment
