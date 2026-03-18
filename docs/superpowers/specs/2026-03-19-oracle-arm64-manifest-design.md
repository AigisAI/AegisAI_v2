# Oracle ARM64 Manifest Guard Design

## Goal

Prevent Oracle Cloud ARM64 deployments from reaching the SSH deploy step when the pushed GHCR images do not actually include both `linux/amd64` and `linux/arm64` manifests.

## Problem

The CD pipeline now requests multi-architecture builds, but the failure mode shown in production happened later during `docker compose pull` on the Oracle VPS:

- the VPS is `linux/arm64`
- the image tag being deployed did not contain a matching `arm64` manifest
- the workflow only discovered this after connecting to the server

That means we need a guard inside GitHub Actions that verifies the published manifests before any remote deploy work starts.

## Approach

Add an explicit verification step in `.github/workflows/cd.yml` after the API and web images are pushed. The step will:

1. inspect each pushed GHCR tag with `docker buildx imagetools inspect`
2. assert that both `linux/amd64` and `linux/arm64` are present
3. fail the workflow before the deploy job if either architecture is missing

## Testing

Add a regression assertion in `test/github-actions/cd-workflow.test.mjs` that requires:

- a manifest verification step in the CD workflow
- `docker buildx imagetools inspect`
- checks for both `linux/amd64` and `linux/arm64`

This keeps the manifest guard from silently disappearing in future workflow edits.
