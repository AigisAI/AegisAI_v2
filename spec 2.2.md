# Aegisai Platform — Agent Development Specification

> **문서 유형:** AI 에이전트 개발 착수용 기술 명세서  
> **버전:** v2.1.1 (NestJS 스택 전환 및 명세 정합성 수정본)  
> **기준 PRD:** PRD_Aegisai_Platform v2.0  
> **작성일:** 2026-03-11

---

## ⚠️ 에이전트 착수 전 필독 — 핵심 제약 조건

1. 분석 대상 언어는 **현재 Java만 허용**한다. 단, 서비스 코드 전반에서 언어 분기 문자열을 직접 하드코딩하지 말고 `ILanguageHandler` 플러그인 구조를 통해 처리한다.
2. **코드 파일 직접 업로드 기능은 구현하지 않는다.** 분석 대상 코드�� 사용자가 업로드하지 않으며, 연동된 GitHub/GitLab 저장소의 clone/API 접근을 통해 수집한다.
3. **취약점 탐지 로직은 SaaS 백엔드(apps/api)에서 직접 구현하지 않는다.** 백엔드는 `IAnalysisApiClient` 인터페이스를 통해 외부 분석 시스템에 위임한다. Phase 1 기본 구현은 `MockAnalysisApiClient`이며, `apps/ai` 연동은 선택적 통합 경로로 제공한다.
4. 프론트엔드와 백엔드는 모두 TypeScript를 사용하며, 공유 타입은 `packages/shared` 패키지에서 관리한다.
5. 모든 인터페이스와 추상화는 **확장성 우선**으로 설계한다.

---

## 목차

1. 프로젝트 개요
2. 기술 스택
3. 시스템 아키텍처
4. Monorepo 디렉토리 구조
5. Prisma 스키마
6. API 명세 (MVP)
7. Analysis API 명세
8. 핵심 모듈 설계
9. GitHub/GitLab 연동 플로우
10. 개발 환경 설정
11. 개발 태스크 (Phase별)
12. 코딩 컨벤션
13. 테스트 전략
14. 부록

---

## 1. 프로젝트 개요

Aegisai는 GitHub/GitLab 레포지토리를 연동하여 **Java 코드의 보안 취약점을 자동 탐지**하고, AI가 수정 코드를 제안하는 SaaS 플랫폼이다.

### 1.1 MVP 핵심 기능 (이번 구현 범위)

| # | 기능 | 설명 |
|---|------|------|
| 1 | GitHub/GitLab OAuth 연동 | 사용자 인증 및 레포 목록 조회 |
| 2 | 레포 스캔 요청 | 선택한 레포/브랜치를 분석 API에 전달 |
| 3 | AI Consensus 앙상블 탐지 | 2개 이상 LLM 교차 검증 결과를 표현할 수 있는 데이터 구조 제공. Phase 1 기본 구현은 Mock 결과 반환 |
| 4 | 취약점 결과 저장 및 조회 | 분석 API 결과를 DB에 저장, UI에 제공 |
| 5 | 대시보드 | 취약점 현황 요약 (심각도별 분포, 추이) |
| 6 | 취약점 상세 | 파일·라인·코드 스니펫·수정 제안·신뢰도 점수 표시 |
| 7 | 스캔 히스토리 | 프로젝트별 스캔 이력 관리 |

### 1.2 이번 구현에서 제외

- 코드 파일 직접 업로드
- SaaS 백엔드 내부의 자체 취약점 탐지 엔진 구현
- PDF 리포트 내보내기
- RBAC / 팀 기능
- 실시간 스캔 상태 스트리밍(WebSocket/SSE)
- 피드백 기반 앙상블 가중치 자동 학습
- GitHub PR 자동 트리거 스캔 기능의 실제 운영 적용
- GitHub Suggested Changes의 실제 운영 적용

> `apps/ai`, GitHub Webhook, Suggested Changes 관련 내용은 **향후 확장 또는 선택 통합 경로를 위한 설계 명세**로 문서에 포함한다. 기본 Phase 1 구현 완료 기준은 `MockAnalysisApiClient` 기반 동작이다.

### 1.3 성공 기준 (Success Metrics)

| 지표 | 목표값 |
|------|--------|
| 사용성 | GitHub 연동 후 첫 PR 분석까지 1분 이내 |
| 분석 속도 | 코드 1,000라인당 분석 + 패치 생성 30초 이내 |
| 효율성 | 수동 코드 리뷰 대비 취약점 수정 시간 50% 단축 |

---

## 2. 기술 스택

### 2.1 Monorepo 구조

```text
pnpm workspace 기반 monorepo
├── apps/api        → NestJS 백엔드
├── apps/web        → React 프론트엔드
├── apps/ai         → FastAPI 기반 AI 분석 서버(선택 통합)
└── packages/shared → 공유 TypeScript 타입
```

> 핵심 장점: `packages/shared`에서 API 요청/응답 타입을 한 번 정의하면 프론트엔드와 백엔드가 동일 타입을 import하여 사용할 수 있다. 단, 런타임 검증용 DTO(class-validator)는 백엔드에서 별도로 관리한다.

### 2.2 Backend (apps/api)

| 항목 | 선택 | 버전 | 이유 |
|------|------|------|------|
| Runtime | Node.js | 20 LTS | 안정성 |
| Framework | NestJS | 10.x | 모듈 구조, DI, 데코레이터 기반 아키텍처 |
| Language | TypeScript | 5.x | 프론트와 타입 공유 |
| ORM | Prisma | 5.x | 타입 자동 생성, 마이그레이션 관리 |
| DB | PostgreSQL | 16 | JSON 컬럼, 풍부한 인덱스 |
| Cache | node-cache | - | MVP 범용 조회 캐시 |
| Auth | Passport.js + NestJS OAuth2 | - | GitHub/GitLab OAuth2 |
| HTTP Client | Axios + @nestjs/axios | 1.x | GitHub/GitLab API, AI 서버 호출 |
| Validation | class-validator + class-transformer | - | DTO 유효성 검사 |
| API Docs | @nestjs/swagger | - | `/api-docs` 자동 생성 |
| Queue | BullMQ | 5.x | 비동기 스캔 Job 처리 |
| Rate Limiting | @nestjs/throttler | 5.x | API 요청 제한 |
| Logging | NestJS Logger | - | 개발: debug, 운영: info |
| Testing | Jest + Supertest + Testcontainers | - | 단위/통합 테스트 |

> Redis는 **Phase 1부터 Queue와 Session Store 용도**로 사용한다. 일반 API 응답 캐시는 MVP 단계에서는 `node-cache`를 사용하고, Phase 2에서 Redis 기반 범용 캐시 전환을 검토한다.

### 2.3 Frontend (apps/web)

| 항목 | 선택 | 버전 |
|------|------|------|
| Framework | React | 18.x |
| Language | TypeScript | 5.x |
| Build | Vite | 5.x |
| UI Library | shadcn/ui + Tailwind CSS | latest |
| Server State | TanStack Query | 5.x |
| Client State | Zustand | 4.x |
| HTTP Client | Axios (shared instance) | 1.x |
| Router | React Router | 6.x |
| Charts | Recharts | 2.x |

### 2.4 AI 서버 (apps/ai, 선택 통합)

| 항목 | 선택 | 버전 |
|------|------|------|
| Framework | FastAPI | latest |
| Language | Python | 3.11+ |
| ASGI | Uvicorn | latest |
| HTTP Client | httpx | latest |

### 2.5 Infrastructure (로컬 개발)

```yaml
services:
  - PostgreSQL 16
  - Redis 7
  - AI Server (선택)
```

---

## 3. 시스템 아키텍처

```text
┌──────────────────────────────────────────────────────────────┐
│                    Browser (React SPA)                      │
│               apps/web — TypeScript + React                 │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / REST
                            │ shared types: packages/shared
┌───────────────────────────▼──────────────────────────────────┐
│                  NestJS API Server (apps/api)               │
│                                                              │
│  AuthModule / RepoModule / ScanModule / DashboardModule      │
│  VulnerabilityModule / HealthModule                          │
│                                                              │
│  ScanService → BullMQ Queue → ScanProcessor                  │
│                  │                                           │
│                  ├─ IGitProviderClient                       │
│                  └─ IAnalysisApiClient                       │
└──────────┬───────────────────────┬───────────────────────────┘
           │                       │
┌──────────┴──────────┐   ┌───────┴────────────────────────────┐
│ PostgreSQL (Prisma) │   │ Analysis Backend                   │
│ Redis (Queue/Session)│  │ - MockAnalysisApiClient (기본)     │
└─────────────────────┘   │ - apps/ai via InternalAnalysisApiClient (선택) |
                          └────────────────────────────────────┘
```

### 3.1 핵심 설계 원칙

1. **분석 시스템 분리**: `IAnalysisApiClient` 인터페이스를 통해서만 분석을 요청한다. Phase 1 기본값은 `MockAnalysisApiClient`이다.
2. **Consensus 데이터 모델 보존**: 단일 모델 결과만 저장하는 구조가 아니라, `consensusScore` 및 `modelResults`를 저장할 수 있는 데이터 구조를 유지한다.
3. **언어 확장 플러그인 구조**: `ILanguageHandler` 인터페이스와 `LanguageHandlerRegistry`를 중심으로 언어별 확장을 수용한다.
4. **스캔 비동기 처리**: `POST /api/scans`는 즉시 `scanId`를 반환하고, 실제 처리는 BullMQ Worker가 수행한다.
5. **Phase 2 확장 예약**: GitHub Webhook 기반 PR 자동 트리거와 Suggested Changes는 문서에 설계만 포함하고, MVP 구현 범위와 구분한다.
6. **타입 공유**: `packages/shared`의 타입을 API 응답 타입과 React 컴포넌트가 동시에 import한다.
7. **CORS 명시 설정**: `FRONTEND_URL` 환경변수로 허용 origin을 관리한다.
8. **Health Check 제공**: `GET /api/health` 엔드포인트로 API 서버 uptime과 DB/Redis 상태를 확인한다.

---

## 4. Monorepo 디렉토리 구조

### 4.1 루트

```text
Aegisai/
├── package.json
├── pnpm-workspace.yaml
├── .npmrc
├── docker-compose.yml
├── .env.example
├── apps/
│   ├── api/
│   ├── web/
│   └── ai/                 # 선택 통합 경로
└── packages/
    └── shared/
        ├── package.json
        └── src/
            ├── index.ts
            └── types/
                ├── common.ts
                ├── auth.ts
                ├── repo.ts
                ├── scan.ts
                ├── vulnerability.ts
                └── dashboard.ts
```

### 4.2 Backend (apps/api)

```text
apps/api/
├── package.json
├── tsconfig.json
├── nest-cli.json
├── prisma/
│   ├── schema.prisma
│   ├── seed.ts
│   └── migrations/
└── src/
    ├── main.ts
    ├── app.module.ts
    ├── config/
    │   ├── config.module.ts
    │   └── config.service.ts
    ├── prisma/
    │   ├── prisma.module.ts
    │   └── prisma.service.ts
    ├── auth/
    │   ├── auth.module.ts
    │   ├── auth.controller.ts
    │   ├── auth.service.ts
    │   ├── auth.serializer.ts
    │   ├── strategies/
    │   │   ├── github.strategy.ts
    │   │   └── gitlab.strategy.ts
    │   ├── guards/
    │   │   └── session-auth.guard.ts
    │   ├── decorators/
    │   │   └── current-user.decorator.ts
    │   └── utils/
    │       └── token-crypto.util.ts
    ├── repo/
    │   ├── repo.module.ts
    │   ├── repo.controller.ts
    │   └── repo.service.ts
    ├── scan/
    │   ├── scan.module.ts
    │   ├── scan.controller.ts
    │   ├── scan.service.ts
    │   └── scan.processor.ts
    ├── webhook/            # Phase 2 reserved
    │   ├── webhook.module.ts
    │   └── webhook.controller.ts
    ├── vulnerability/
    │   ├── vulnerability.module.ts
    │   ├── vulnerability.controller.ts
    │   └── vulnerability.service.ts
    ├── dashboard/
    │   ├── dashboard.module.ts
    │   ├── dashboard.controller.ts
    │   └── dashboard.service.ts
    ├── client/
    │   ├── analysis/
    │   │   ├── analysis-api-client.interface.ts
    │   │   ├── analysis-api.dto.ts
    │   │   ├── mock-analysis-api.client.ts
    │   │   ├── internal-analysis-api.client.ts   # 선택 통합
    │   │   └── analysis-api.module.ts
    │   └── git/
    │       ├── git-provider-client.interface.ts
    │       ├── github.client.ts
    │       ├── gitlab.client.ts
    │       ├── git-client.registry.ts
    │       └── git-client.module.ts
    ├── language/
    │   ├── language-handler.interface.ts
    │   ├── language-handler.registry.ts
    │   └── handlers/
    │       └── java.language-handler.ts
    ├── health/
    │   └── health.controller.ts
    └── common/
        ├── dto/
        │   ├── api-response.dto.ts
        │   └── pagination.dto.ts
        ├── decorators/
        │   └── raw-body.decorator.ts
        ├── filters/
        │   └── global-exception.filter.ts
        └── interceptors/
            └── response-transform.interceptor.ts
```

### 4.3 Frontend (apps/web)

```text
apps/web/
├── package.json
├── vite.config.ts
├── tailwind.config.ts
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── router.tsx
    ├── pages/
    │   ├── LoginPage.tsx
    │   ├── DashboardPage.tsx
    │   ├── ReposPage.tsx
    │   ├── ScanPage.tsx
    │   ├── VulnerabilitiesPage.tsx
    │   └── VulnerabilityDetailPage.tsx
    ├── components/
    ├── hooks/
    ├── api/
    └── store/
```

### 4.4 Shared 패키지 (packages/shared)

```text
packages/shared/
├── package.json   # name: @aegisai/shared
├── tsconfig.json
└── src/
    ├── index.ts
    └── types/
        ├── common.ts
        ├── auth.ts
        ├── repo.ts
        ├── scan.ts
        ├── vulnerability.ts
        └── dashboard.ts
```

### 4.5 AI 서버 (apps/ai, 선택 통합)

```text
apps/ai/
├── main.py
├── requirements.txt
├── Dockerfile
├── .env
├── routers/
│   ├── analyze.py
│   └── health.py
├── models/
│   ├── base.py
│   ├── finetuned_a.py
│   ├── finetuned_b.py
│   └── registry.py
├── consensus/
│   └── engine.py
├── schemas/
│   ├── request.py
│   └── response.py
└── training/
```

> 원칙:
> - `apps/ai`는 선택 통합 경로이며, Phase 1 완료의 필수 조건은 아니다.
> - Dockerfile 작성 시 `git` 패키지를 설치해야 한다.
> - `training/` 디렉토리는 배포 이미지에 포함하지 않는다.
> - `schemas/`의 `AnalyzeRequest` / `AnalyzeResponse`는 NestJS 측 타입과 필드명·타입을 일치시킨다.

---

## 5. Prisma 스키마

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum RepoProvider {
  GITHUB
  GITLAB
}

enum ScanStatus {
  PENDING
  RUNNING
  DONE
  FAILED
}

enum Severity {
  CRITICAL
  HIGH
  MEDIUM
  LOW
  INFO
}

enum VulnStatus {
  OPEN
  FIXED
  ACCEPTED
  REJECTED
}

enum UserFeedback {
  ACCEPTED
  REJECTED
}

model User {
  id             String          @id @default(uuid())
  email          String?         @unique
  name           String
  avatarUrl      String?
  createdAt      DateTime        @default(now())
  updatedAt      DateTime        @updatedAt
  oauthTokens    OAuthToken[]
  connectedRepos ConnectedRepo[]
}

model OAuthToken {
  id             String       @id @default(uuid())
  userId         String
  provider       RepoProvider
  providerUserId String
  accessToken    String
  refreshToken   String?
  expiresAt      DateTime?
  createdAt      DateTime     @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([userId, provider])
  @@unique([provider, providerUserId])
}

model ConnectedRepo {
  id             String       @id @default(uuid())
  userId         String
  provider       RepoProvider
  providerRepoId String
  fullName       String
  cloneUrl       String
  defaultBranch  String       @default("main")
  isPrivate      Boolean      @default(false)
  connectedAt    DateTime     @default(now())
  updatedAt      DateTime     @updatedAt

  user  User   @relation(fields: [userId], references: [id], onDelete: Cascade)
  scans Scan[]

  @@unique([userId, provider, providerRepoId])
}

model Scan {
  id              String       @id @default(uuid())
  connectedRepoId String
  branch          String
  commitSha       String?
  status          ScanStatus   @default(PENDING)
  language        String       @default("java")
  totalFiles      Int?
  totalLines      Int?
  vulnCritical    Int          @default(0)
  vulnHigh        Int          @default(0)
  vulnMedium      Int          @default(0)
  vulnLow         Int          @default(0)
  vulnInfo        Int          @default(0)
  errorMessage    String?
  startedAt       DateTime?
  completedAt     DateTime?
  createdAt       DateTime     @default(now())
  updatedAt       DateTime     @updatedAt

  connectedRepo   ConnectedRepo   @relation(fields: [connectedRepoId], references: [id], onDelete: Cascade)
  vulnerabilities Vulnerability[]

  @@index([connectedRepoId])
  @@index([status])
  @@index([createdAt(sort: Desc)])
}

model Vulnerability {
  id                 String        @id @default(uuid())
  scanId             String
  title              String
  description        String
  severity           Severity
  filePath           String
  lineStart          Int
  lineEnd            Int?
  codeSnippet        String?
  fixSuggestion      String?
  fixExplanation     String?
  cweId              String?
  cveId              String?
  owaspCategory      String?
  referenceLinks     Json?
  consensusScore     Float?
  modelResults       Json?
  status             VulnStatus    @default(OPEN)
  userFeedback       UserFeedback?
  createdAt          DateTime      @default(now())
  updatedAt          DateTime      @updatedAt

  scan Scan @relation(fields: [scanId], references: [id], onDelete: Cascade)

  @@index([scanId])
  @@index([severity])
  @@index([status])
}
```

### 5.1 스키마 설계 주의사항

- `providerRepoId`는 GitHub/GitLab의 ID 타입 차이를 흡수하기 위해 문자열로 저장한다.
- `Scan.language`는 확장성을 위해 문자열로 유지하되, 애플리케이션 레벨에서는 `LanguageHandlerRegistry`에 등록된 언어만 허용한다.
- 동일 `ConnectedRepo`에 대해 동시에 하나의 활성 스캔만 허용하는 정책은 **서비스 레벨 규칙**이다. DB 레벨 유니크 제약이 아니라는 점을 명시한다.
- `userFeedback`는 사용자 판단 데이터를 보존하기 위한 필드이며, `status`는 최종 취약점 처리 상태를 나타낸다. MVP에서는 `PATCH /feedback` 호출 시 `feedback=ACCEPTED`이면 `status=ACCEPTED`, `feedback=REJECTED`이면 `status=REJECTED`로 동기화한다.

---

## 6. API 명세 (MVP)

### 6.1 공통 규칙

- Base URL: `/api`
- 인증: Session Cookie (`connect.sid`)
- 세션 TTL: 24시간 (`maxAge: 86400000`)
- `cookie.secure`: production에서만 `true`
- `cookie.sameSite`: `'lax'`
- `cookie.httpOnly`: `true`
- 페이지네이션 기본값: `page=1`, `size=20`, 최대 `size=100`
- 모든 성공/실패 응답은 `ApiResponse<T>` 래퍼를 사용한다.

```typescript
export interface SuccessResponse<T> {
  success: true;
  data: T;
  message: null;
  timestamp: string;
}

export interface ErrorResponse {
  success: false;
  data: null;
  message: string;
  errorCode: string;
  timestamp: string;
}

export type ApiResponse<T> = SuccessResponse<T> | ErrorResponse;

export interface PageResponse<T> {
  items: T[];
  totalCount: number;
  page: number;
  totalPages: number;
}
```

### 6.2 인증

#### `GET /api/auth/me`

```typescript
// 200
{
  id: string;
  email: string | null;
  name: string;
  avatarUrl: string | null;
  connectedProviders: ('github' | 'gitlab')[];
}
```

#### `POST /api/auth/logout`

```typescript
null
```

#### OAuth2 플로우

```text
GET /api/auth/github
GET /api/auth/github/callback
GET /api/auth/gitlab
GET /api/auth/gitlab/callback
```

성공 시 `FRONTEND_URL/dashboard`로 리다이렉트한다.

### 6.3 레포지토리

#### `GET /api/repos`

```typescript
{
  id: string;
  provider: 'github' | 'gitlab';
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  lastScanAt: string | null;
  lastScanStatus: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED' | null;
}[]
```

#### `GET /api/repos/available?provider=github&page=1&size=30`

- 응답 TTL 5분 캐시 (`node-cache`)
- 외부 Git provider API pagination을 내부 API pagination과 매핑한다.

```typescript
PageResponse<{
  providerRepoId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  alreadyConnected: boolean;
}>
```

#### `POST /api/repos`

```typescript
{
  provider: 'github' | 'gitlab';
  providerRepoId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
}
```

#### `DELETE /api/repos/:repoId`

```typescript
null
```

### 6.4 스캔

#### `POST /api/scans`

```typescript
{
  repoId: string;
  branch: string;
}
```

응답(202):

```typescript
{
  scanId: string;
  status: 'PENDING';
  message: string;
}
```

#### `GET /api/scans/:scanId`

```typescript
{
  id: string;
  repoFullName: string;
  branch: string;
  commitSha: string | null;
  status: 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED';
  language: string;
  totalFiles: number | null;
  totalLines: number | null;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
}
```

#### `GET /api/repos/:repoId/scans?page=1&size=10`

```typescript
PageResponse<ScanSummary>
```

### 6.5 취약점

#### `GET /api/scans/:scanId/vulnerabilities`

지원 쿼리 파라미터 형식:

- `severity=HIGH&severity=LOW` (다중 선택)
- `status=OPEN` (단일 값)
- `page=1`
- `size=20`
- `sort=createdAt:desc` 또는 `sort=severity:asc`

```typescript
PageResponse<{
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineStart: number;
  lineEnd: number | null;
  cweId: string | null;
  owaspCategory: string | null;
  status: 'OPEN' | 'FIXED' | 'ACCEPTED' | 'REJECTED';
}>
```

#### `GET /api/vulnerabilities/:vulnId`

```typescript
{
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineStart: number;
  lineEnd: number | null;
  codeSnippet: string | null;
  fixSuggestion: string | null;
  fixExplanation: string | null;
  cweId: string | null;
  cveId: string | null;
  owaspCategory: string | null;
  referenceLinks: { title: string; url: string }[] | null;
  consensusScore: number | null;
  modelResults: {
    model: string;
    detected: boolean;
    severity: string;
    reasoning: string;
  }[] | null;
  status: 'OPEN' | 'FIXED' | 'ACCEPTED' | 'REJECTED';
  userFeedback: 'ACCEPTED' | 'REJECTED' | null;
}
```

#### `PATCH /api/vulnerabilities/:vulnId/feedback`

```typescript
{
  feedback: 'ACCEPTED' | 'REJECTED';
}
```

응답:

```typescript
{
  id: string;
  status: 'ACCEPTED' | 'REJECTED';
  userFeedback: 'ACCEPTED' | 'REJECTED';
}
```

### 6.6 대시보드

#### `GET /api/dashboard`

```typescript
{
  totalRepos: number;
  totalScans: number;
  openVulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recentScans: ScanSummary[];
  trend: {
    date: string;
    critical: number;
    high: number;
    medium: number;
  }[];
}
```

### 6.7 Health Check

#### `GET /api/health`

```typescript
{
  status: 'ok' | 'degraded';
  uptime: number;
  services: {
    database: 'up' | 'down';
    redis: 'up' | 'down';
  };
  timestamp: string;
}
```

판정 규칙:

- DB와 Redis가 모두 `up`이면 `ok`
- 하나라도 `down`이면 `degraded`

### 6.8 Rate Limiting

- 인증 사용자 기준 100 req/min
- 미인증 사용자 기준 20 req/min
- `POST /api/scans`: 10 req/min

---

## 6.A Phase 2 예약 API

### `POST /api/vulnerabilities/:vulnId/suggest-change`

GitHub PR에 Suggested Changes 코멘트를 삽입하는 예약 엔드포인트이다.

```typescript
{
  prNumber: number;
  repoFullName: string;
}
```

응답:

```typescript
{
  commentId: string;
  htmlUrl: string;
}
```

---

## 7. Analysis API 명세

### 7.1 인터페이스 정의

```typescript
export interface IAnalysisApiClient {
  analyze(request: AnalysisRequest): Promise<AnalysisResult>;
}

export interface AnalysisRequest {
  scanId: string;
  cloneUrl: string;
  branch: string;
  commitSha?: string;
  language: string;     // 현재 허용값은 "java"뿐이지만 인터페��스는 확장 가능해야 함
  accessToken: string;
}

export interface ModelResult {
  model: string;
  detected: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reasoning: string;
}

export interface VulnerabilityItem {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineStart: number;
  lineEnd?: number;
  codeSnippet?: string;
  fixSuggestion?: string;
  fixExplanation?: string;
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  referenceLinks?: { title: string; url: string }[];
  consensusScore: number;
  modelResults: ModelResult[];
}

export interface AnalysisResult {
  scanId: string;
  success: boolean;
  errorMessage?: string;
  totalFiles: number;
  totalLines: number;
  vulnerabilities: VulnerabilityItem[];
}
```

정책:

- `consensusScore`는 응답 계약상 필수 값으로 취급한다.
- 실 구현에서 결과 필터링 기준은 `consensusScore >= 0.5`이다.
- `detected=false`인 모델 결과는 `severity='INFO'`를 기본값으로 사용한다.

### 7.2 Mock 구현체

- Phase 1 기본 구현은 `MockAnalysisApiClient`이다.
- `3~8초` 지연을 시뮬레이션한다.
- `consensusScore`와 `modelResults`를 포함한 예시 데이터를 반환한다.

### 7.3 AnalysisApiModule 등록 원칙

- 기본 바인딩은 `MockAnalysisApiClient`
- `USE_INTERNAL_AI=true`일 때만 `InternalAnalysisApiClient`로 전환 가능
- 이 전환은 서비스 레이어가 아니라 모듈 바인딩 변경으로 처리한다.
- `InternalAnalysisApiClient` 사용 시 `HttpModule`과 `@nestjs/axios`를 반드시 등록한다.

### 7.4 apps/ai — 선택 통합 명세

`apps/ai`는 향후 또는 선택적 통합을 위한 FastAPI 서버이다. Phase 1 기본 완료 기준에는 포함되지 않는다.

```python
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

핵심 원칙:

1. `AnalyzeRequest` / `AnalyzeResponse`의 필드명과 타입은 NestJS 타입과 1:1로 맞춘다.
2. `ConsensusEngine`은 `filePath + lineStart` 기준으로 취약점을 묶는다.
3. `consensusScore < 0.5` 항목은 반환하지 않는다.
4. AI 서버 컨테이너에는 `git` 패키지를 설치한다.

---

## 8. 핵심 모듈 설계

### 8.1 ScanService + ScanProcessor 흐름

BullMQ 정책:

- 동시성: `3`
- Job 타임아웃: `300000ms`
- 재시도: `1`

주의:

- 동일 레포 활성 스캔 중복 방지는 서비스 레벨 규칙이다.
- 경쟁 상태를 줄이기 위해 transaction 또는 락 전략을 검토한다.
- 최소 MVP에서는 중복 검사 후 생성 방식으로 구현하되, 운영 환경에서는 advisory lock 또는 queue deduplication 도입을 권장한다.

```typescript
@Injectable()
export class ScanService {
  constructor(
    private prisma: PrismaService,
    @InjectQueue('scan-jobs') private scanQueue: Queue,
  ) {}

  async requestScan(userId: string, repoId: string, branch: string) {
    const repo = await this.prisma.connectedRepo.findFirst({
      where: { id: repoId, userId },
    });

    if (!repo) {
      throw new NotFoundException('연동된 레포를 찾을 수 없습니다.');
    }

    const active = await this.prisma.scan.findFirst({
      where: {
        connectedRepoId: repoId,
        status: { in: ['PENDING', 'RUNNING'] },
      },
    });

    if (active) {
      throw new ConflictException('이미 대기 중이거나 실행 중인 스캔이 있습니다.');
    }

    const scan = await this.prisma.scan.create({
      data: {
        connectedRepoId: repoId,
        branch,
        status: 'PENDING',
      },
    });

    await this.scanQueue.add('execute-scan', { scanId: scan.id }, {
      jobId: scan.id,
      attempts: 1,
      timeout: 300000,
    });

    return {
      scanId: scan.id,
      status: 'PENDING' as const,
      message: '스캔이 대기열에 등록되었습니다.',
    };
  }
}
```

구현 주의사항:

- Processor에서 `scan` 조회 결과 null 여부를 확인한다.
- `OAuthToken.accessToken`은 저장 시 암호화, 사용 시 복호화한다.
- Prisma `Json` 컬럼 저장 시 `Prisma.InputJsonValue` 명시 캐스팅을 적용한다.
- `createMany` 시에는 nullable 필드를 명시적으로 매핑한다.
- Axios 계열 오류는 `AxiosError` narrowing 후 상태 코드를 분기한다.

### 8.2 ILanguageHandler 구조

```typescript
export interface ILanguageHandler {
  getLanguage(): string;
  getFileExtensions(): string[];
  preProcess?(request: AnalysisRequest): AnalysisRequest;
}
```

원칙:

- 현재 구현체는 `JavaLanguageHandler` 하나만 둔다.
- 도메인 로직에 언어 문자열을 산발적으로 직접 비교하지 않는다.

### 8.3 Git Provider 클라이언트 구조

- 인터페이스: `IGitProviderClient`
- 구현체: `GithubClient`, `GitlabClient`
- 조회기: `GitClientRegistry`

원칙:

- 외부 API pagination과 내부 페이지네이션을 매핑한다.
- 401은 토큰 만료/무효 가능성으로 처리한다.
- 404는 레포 접근 불가 또는 삭제로 처리한다.

---

## 9. GitHub/GitLab 연동 플로우

### 9.1 환경 변수 설정

```bash
GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx
GITLAB_CLIENT_ID=xxx
GITLAB_CLIENT_SECRET=xxx
```

### 9.2 OAuth와 Webhook의 역할 구분

- **GitHub OAuth App / GitLab OAuth Application**: 사용자의 로그인 및 저장소 접근 권한 획득에 사용한다.
- **GitHub Webhook 또는 GitHub App Webhook**: PR 이벤트 자동 감지에 사용한다.
- 두 설정은 별개이며, OAuth 설정만으로 Webhook이 자동 구성되지는 않는다.

### 9.3 Passport Strategy 원칙

- 콜백 URL은 `APP_URL` 기준 `/api/auth/{provider}/callback`
- OAuth 성공 시 `FRONTEND_URL/dashboard`로 리다이렉트
- 세션 기반 인증을 사용하므로 serializer / deserializer 구현이 필요하다.

### 9.4 GitHub API 호출 기본 헤더

```typescript
{
  Authorization: `Bearer ${accessToken}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
}
```

### 9.5 GitHub Webhook — Phase 2 예약

- 실제 경로는 global prefix 포함 `/api/webhook/github`
- raw body 기반 HMAC-SHA256 검증 필요
- `pull_request` 이벤트의 `opened`, `synchronize`만 우선 처리

### 9.6 GitHub Suggested Changes — Phase 2 예약

- 단일 라인 코멘트에는 `start_line`을 포함하지 않는다.
- 멀티 라인 코멘트일 때만 `start_line`을 설정한다.
- unified diff를 GitHub suggestion 블록으로 변환하는 유틸이 필요하다.

---

## 10. 개발 환경 설정

### 10.1 사전 요구사항

```bash
Node.js 20 LTS
pnpm 9.x
Docker Desktop
```

패키지 매니저 고정:

- 루트 `package.json`에 `"packageManager": "pnpm@9.15.4"` 명시
- `.npmrc`에 `engine-strict=true` 설정

### 10.2 docker-compose.yml

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: aegisai
      POSTGRES_USER: aegisai
      POSTGRES_PASSWORD: aegisai
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  ai-server:
    build:
      context: ./apps/ai
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - AI_SERVER_PORT=8000
    volumes:
      - ./apps/ai:/app
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

volumes:
  postgres_data:
```

### 10.3 루트 package.json / workspace 정책

```json
{
  "name": "aegisai",
  "private": true,
  "packageManager": "pnpm@9.15.4",
  "scripts": {
    "dev": "concurrently \"pnpm --filter @aegisai/api dev\" \"pnpm --filter @aegisai/web dev\"",
    "build": "pnpm --filter @aegisai/shared build && pnpm --filter @aegisai/api build && pnpm --filter @aegisai/web build",
    "db:migrate": "pnpm --filter @aegisai/api prisma migrate dev",
    "db:studio": "pnpm --filter @aegisai/api prisma studio"
  }
}
```

```yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

### 10.4 CORS / Session / Passport 설정 주의사항

- CORS: `origin = FRONTEND_URL`, `credentials = true`
- Session middleware, Passport initialize, Passport session을 모두 등록한다.
- Redis store는 `connect-redis` 등 호환 가능한 라이브러리로 구성한다.

### 10.5 실행 순서

```bash
pnpm install
docker-compose up -d
pnpm db:migrate
pnpm dev
```

---

## 11. 개발 태스크 (Phase별)

### Phase 1 �� 기반 구조 (필수 구현)

```text
[ ] TASK-01: Monorepo 초기화
[ ] TASK-02: Prisma 설정 및 DB 마이그레이션
[ ] TASK-03: 공유 타입 패키지 구성
[ ] TASK-04: OAuth2 인증 구현
[ ] TASK-05: IAnalysisApiClient 인터페이스 + Mock 구현
[ ] TASK-06: ILanguageHandler 플러그인 구조
[ ] TASK-07: IGitProviderClient 구현
[ ] TASK-08: BullMQ 스캔 큐 + ScanProcessor 구현
[ ] TASK-09: Repo API
[ ] TASK-10: Scan API
[ ] TASK-11: Vulnerability API
[ ] TASK-12: Dashboard API
[ ] TASK-13: 공통 처리
[ ] TASK-14: Health Check + DB 시드
```

### Phase 2 — 예약 기능

```text
[ ] TASK-15-P2: GitHub Webhook — PR 자동 트리거
[ ] TASK-16-P2: GitHub Suggested Changes
[ ] TASK-21-P2: 피드백 기반 앙상블 가중치 자동 학습
```

### Phase 3 — Frontend

```text
[ ] TASK-17: 레이아웃 및 공통 설정
[ ] TASK-18: 인증 플로우
[ ] TASK-19: 레포 연동 페이지
[ ] TASK-20: 스캔 실행 및 상태
[ ] TASK-21: 취약점 목록 및 상세
[ ] TASK-22: 대시보드
```

---

## 12. 코딩 컨벤션

### Backend

```typescript
// 1. 외부 의존성은 인터페이스로 추상화
// 2. DTO는 class-validator 사용
// 3. 비즈니스 로직은 Service에 집중
// 4. Prisma 쿼리는 Service에서만 직접 사용
// 5. 환경 변수는 ConfigService를 통해 접근
// 6. 로깅은 NestJS Logger 사용
// 7. 페이지네이션 기본 size=20, 최대 size=100
```

### Frontend

```typescript
import type { VulnerabilityDetail } from '@aegisai/shared';
```

원칙:

- 서버 상태는 TanStack Query, 클라이언트 상태는 Zustand 사용
- API 함수는 `api/` 디렉토리에 집중
- 401 처리는 Axios 인터셉터에서 담당하고, 일반 에러 토스트는 Query 글로벌 에러 처리에서 담당하여 역할을 분리한다.
- `ProtectedRoute`는 React Router v6 wrapper component 패턴으로 구현한다.

---

## 13. 테스트 전략

| 레이어 | 도구 | 핵심 테스트 |
|--------|------|-------------|
| 단위 (Backend) | Jest | ScanService, MockAnalysisApiClient |
| 통합 (Backend) | Supertest + Testcontainers | API E2E, DB/Redis 연동 |
| 단위 (Frontend) | Vitest + RTL | 주요 UI 컴포넌트 |
| API Mocking | MSW | 프론트 개발 및 테스트 |

핵심 원칙:

- OAuth 통합 테스트는 실제 외부 provider 호출 대신 strategy/service mock 기반으로 수행한다.
- BullMQ 통합 테스트에는 실제 Redis 컨테이너 사용을 권장한다.
- `POST /api/scans` 중복 요청, `AuthGuard` 401, ScanProcessor 저장 흐름을 우선 검증한다.

---

## 14. 부록

### 부록 A. 환경 변수 목록

| 변수명 | 필수 | 설명 |
|--------|------|------|
| `DATABASE_URL` | ✅ | Prisma PostgreSQL URL |
| `REDIS_URL` | ✅ | BullMQ / Session Redis URL |
| `SESSION_SECRET` | ✅ | 세션 서명 키 |
| `GITHUB_CLIENT_ID` | ✅ | GitHub OAuth App ID |
| `GITHUB_CLIENT_SECRET` | ✅ | GitHub OAuth App Secret |
| `GITLAB_CLIENT_ID` | ✅ | GitLab OAuth Application ID |
| `GITLAB_CLIENT_SECRET` | ✅ | GitLab OAuth Application Secret |
| `APP_URL` | ✅ | API 서버 Base URL |
| `FRONTEND_URL` | ✅ | 프론트엔드 Base URL |
| `TOKEN_ENCRYPTION_KEY` | ✅ | OAuth 토큰 AES-256-GCM 암호화 키 |
| `NODE_ENV` | ✅ | development / production |
| `AI_SERVER_URL` | - | Internal AI 서버 URL |
| `USE_INTERNAL_AI` | - | `true`면 `InternalAnalysisApiClient` 사용 |
| `INTERNAL_API_SECRET` | - | 내부 AI 호출 인증 시크릿 |
| `GITHUB_APP_WEBHOOK_SECRET` | - | GitHub Webhook 서명 키 |

### 부록 B. 완료 체크리스트

```text
시작 전:
[ ] docker-compose up -d 실행
[ ] PostgreSQL, Redis 정상 동작 확인
[ ] GitHub OAuth App / GitLab OAuth Application 설정
[ ] apps/api/.env 작성
[ ] pnpm install
[ ] pnpm db:migrate

Phase 1 완료 기준:
[ ] MockAnalysisApiClient를 통한 스캔 E2E 동작
[ ] GET /api/scans/:id → DONE + 취약점 데이터 반환 확인
[ ] GET /api/health → DB·Redis 연결 상태 확인

선택 통합 검증:
[ ] USE_INTERNAL_AI=true 설정 시 apps/ai /analyze 호출 동작 확인

Phase 2 완료 기준:
[ ] Webhook → PR 이벤트 수신 → 자동 스캔 Job 등록 확인
[ ] Suggested Changes 코멘트 생성 확인

Phase 3 완료 기준:
[ ] 로그인 → 레포 연동 → 스캔 → 취약점 상세 전체 플로우 동작
```

---

문서와 실제 구현이 달라질 경우, 변경 사유를 PR 또는 ADR(Architecture Decision Record)에 기록한다.
