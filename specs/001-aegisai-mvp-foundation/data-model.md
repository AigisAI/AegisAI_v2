# Data Model: AegisAI Platform MVP Foundation

## Core Entities

### User

- **Purpose**: Represents an authenticated SaaS user.
- **Key fields**:
  - `id`
  - `email`
  - `displayName`
  - `avatarUrl`
  - `createdAt`
  - `updatedAt`
- **Relationships**:
  - One-to-many with `OAuthToken`
  - One-to-many with `ConnectedRepo`

### OAuthToken

- **Purpose**: Stores encrypted provider credentials and identity metadata.
- **Key fields**:
  - `id`
  - `userId`
  - `provider` (`GITHUB` or `GITLAB`)
  - `providerUserId`
  - `encryptedAccessToken`
  - `refreshToken` (nullable if provider flow does not use it)
  - `expiresAt` (nullable)
  - `createdAt`
  - `updatedAt`
- **Validation rules**:
  - One active token record per user and provider identity pair
  - Tokens must never be logged in plaintext

### ConnectedRepo

- **Purpose**: Represents a repository linked by a user for scanning.
- **Key fields**:
  - `id`
  - `userId`
  - `provider`
  - `providerRepoId`
  - `name`
  - `owner`
  - `defaultBranch`
  - `installationUrl` or `webUrl`
  - `createdAt`
  - `updatedAt`
- **Validation rules**:
  - One unique connected record per user and provider repository

### Scan

- **Purpose**: Tracks a queued or completed analysis request.
- **Key fields**:
  - `id`
  - `repoId`
  - `userId`
  - `provider`
  - `branch`
  - `commitSha`
  - `status` (`PENDING`, `RUNNING`, `DONE`, `FAILED`)
  - `requestedAt`
  - `startedAt`
  - `completedAt`
  - `totalFiles`
  - `totalLines`
  - `summaryJson`
  - `errorMessage`
- **Validation rules**:
  - Duplicate active scans for the same repo and branch are blocked
  - `completedAt` is required when status is terminal

### Vulnerability

- **Purpose**: Stores a single scan finding.
- **Key fields**:
  - `id`
  - `scanId`
  - `title`
  - `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - `status` (`OPEN`, `FIXED`, `ACCEPTED`, `REJECTED`)
  - `ruleId`
  - `filePath`
  - `lineStart`
  - `lineEnd`
  - `codeSnippet`
  - `description`
  - `recommendation`
  - `confidenceScore`
  - `consensusScore`
  - `modelResultsJson`
  - `feedback`
  - `createdAt`
  - `updatedAt`
- **Validation rules**:
  - `consensusScore` and `modelResultsJson` remain present even in mock mode
  - Feedback transitions are limited to supported enum values

### Report

- **Purpose**: Tracks asynchronously generated PDF exports.
- **Key fields**:
  - `id`
  - `scanId`
  - `status` (`GENERATING`, `READY`, `FAILED`)
  - `storagePath`
  - `downloadUrl`
  - `createdAt`
  - `expiresAt`
  - `errorMessage`
- **Validation rules**:
  - Reports can only be requested for scans with `DONE` status
  - Expired reports return a gone-style response

## Supporting Concepts

### Provider Repository Listing

- External provider DTO normalized into frontend-friendly shared types
- Must support pagination and provider-specific IDs

### Analysis Request Payload

- Includes `scanId`, `language`, and normalized `files[]`
- `files[]` contains path, content, size, and metadata already filtered by backend rules

### Dashboard Summary

- Aggregated over stored scan and vulnerability records
- Includes severity counts, rolling trend points, and recent scan list entries

## Relationships

- `User` 1 -> many `OAuthToken`
- `User` 1 -> many `ConnectedRepo`
- `ConnectedRepo` 1 -> many `Scan`
- `Scan` 1 -> many `Vulnerability`
- `Scan` 1 -> many `Report`

## State Transitions

### Scan Status

- `PENDING` -> `RUNNING`
- `RUNNING` -> `DONE`
- `RUNNING` -> `FAILED`
- `PENDING` -> `FAILED` only if job setup fails before execution begins

### Report Status

- `GENERATING` -> `READY`
- `GENERATING` -> `FAILED`

### Vulnerability Feedback Status

- `OPEN` -> `ACCEPTED`
- `OPEN` -> `REJECTED`
- `OPEN` -> `FIXED` only when future workflow supports it without changing MVP assumptions
