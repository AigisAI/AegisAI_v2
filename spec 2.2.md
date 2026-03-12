# Aegisai Platform — Agent Development Specification

> **문서 유형:** AI 에이전트 개발 착수용 기술 명세서
> **버전:** v2.6 (v2.5 리뷰 반영 — 보안·에러 처리·테스트·구조 개선 17건 보완)
> **기준 PRD:** PRD_Aegisai_Platform v2.0
> **작성일:** 2026-03-11

---

## ⚠️ 에이전트 착수 전 필독 — 핵심 제약 조건

1. 분석 대상 언어는 **현재 Java만 허용**한다. 단, 서비스 코드 전반에서 언어 분기 문자열을 직접 하드코딩하지 말고 `ILanguageHandler` 플러그인 구조를 통해 처리한다.
2. **코드 파일 직접 업로드 기능은 구현하지 않는다.** 분석 대상 코드는 연동된 GitHub/GitLab 저장소의 clone/API 접근을 통해 수집한다.
3. **취약점 탐지 로직은 SaaS 백엔드(apps/api)에서 직접 구현하지 않는다.** 백엔드는 `IAnalysisApiClient` 인터페이스를 통해 외부 분석 시스템에 위임한다. Phase 1 기본 구현은 `MockAnalysisApiClient`이며, `apps/ai` 연동은 선택적 통합 경로로 제공한다.
4. 프론트엔드와 백엔드는 모두 TypeScript를 사용하며, 공유 타입은 `packages/shared` 패키지에서 관리한다.
5. 모든 인터페이스와 추상화는 **확장성 우선**으로 설계한다.

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [기술 스택](#2-기술-스택)
3. [시스템 아키텍처](#3-시스템-아키텍처)
   - 3.1 [핵심 설계 원칙](#31-핵심-설계-원칙)
   - 3.2 [스캔 플로우 시퀀스 다이어그램](#32-스캔-플로우-시퀀스-다이어그램)
   - 3.3 [OAuth 인증 플로우 시퀀스 다이어그램](#33-oauth-인증-플로우-시퀀스-다이어그램)
4. [Monorepo 디렉토리 구조](#4-monorepo-디렉토리-구조)
5. [Prisma 스키마](#5-prisma-스키마)
6. [API 명세 (MVP)](#6-api-명세-mvp)
7. [Analysis API 명세](#7-analysis-api-명세)
8. [핵심 모듈 설계](#8-핵심-모듈-설계)
   - 8.1 [ScanService + ScanProcessor 흐름](#81-scanservice--scanprocessor-흐름)
   - 8.2 [ILanguageHandler — 언어 확장 구조](#82-ilanguagehandler--언어-확장-구조)
   - 8.3 [Git Provider 클라이언트 구조](#83-git-provider-클라이언트-구조)
   - 8.4 [에러 시나리오 및 복구 전략](#84-에러-시나리오-및-복구-전략)
9. [GitHub/GitLab 연동 플로우](#9-githubgitlab-연동-플로우)
10. [개발 환경 설정](#10-개발-환경-설정)
11. [개발 태스크 (Phase별)](#11-개발-태스크-phase별)
12. [코딩 컨벤션](#12-코딩-컨벤션)
13. [테스트 전략](#13-테스트-전략)
14. [부록](#14-부록)

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
- 실시간 스캔 상태 스트리밍 (WebSocket/SSE)
- 피드백 기반 앙상블 가중치 자동 학습
- GitHub PR 자동 트리거 스캔 기능의 실제 운영 적용
- GitHub Suggested Changes의 실제 운영 적용

> `apps/ai`, GitHub Webhook, Suggested Changes 관련 내용은 **향후 확장 또는 선택 통합 경로를 위한 설계 명세**로 문서에 포함한다. 기본 Phase 1 구현 완료 기준은 `MockAnalysisApiClient` 기반 동작이다.

> CI/CD 및 배포 파이프라인은 MVP 완성 후 별도 문서로 정의한다.

### 1.3 성공 기준 (Success Metrics)

| 지표 | 목표값 |
|------|--------|
| 사용성 | GitHub 연동 후 첫 PR 분석까지 **1분 이내** |
| 분석 속도 | 코드 1,000라인당 분석 + 패치 생성 **30초 이내** |
| 효율성 | 수동 코드 리뷰 대비 취약점 수정 시간 **50% 단축** |

---

## 2. 기술 스택

### 2.1 Monorepo 구조

```text
pnpm workspace 기반 monorepo
├── apps/api        → NestJS 백엔드
├── apps/web        → React 프론트엔드
├── apps/ai         → FastAPI 기반 AI 분석 서버 (선택 통합)
└── packages/shared → 공유 TypeScript 타입
```

> **핵심 장점:** `packages/shared`에서 API 요청/응답 타입을 한 번 정의하면 프론트엔드와 백엔드가 동일 타입을 import하여 사용할 수 있다. 단, 런타임 검증용 DTO(class-validator)는 백엔드에서 별도로 관리한다.

### 2.2 Backend (apps/api)

| 항목 | 선택 | 버전 | 이유 |
|------|------|------|------|
| Runtime | Node.js | 20 LTS | 안정성 |
| Framework | NestJS | 10.x | 모듈 구조, DI, 데코레이터 — Spring과 유사한 구조 |
| Language | TypeScript | 5.x | 프론트와 타입 공유 |
| ORM | Prisma | 5.x | 타입 자동 생성, 마이그레이션 관리 |
| DB | PostgreSQL | 16 | JSON 컬럼, 풍부한 인덱스 |
| Cache | node-cache | - | MVP 단계 in-memory 캐시 (Phase 2에서 Redis 전환 검토) |
| Auth | Passport.js + NestJS OAuth2 | - | GitHub/GitLab OAuth2 |
| HTTP Client | Axios + @nestjs/axios | 1.x | GitHub/GitLab API, AI 서버 호출 |
| Validation | class-validator + class-transformer | - | DTO 유효성 검사 |
| API Docs | @nestjs/swagger | - | `/api-docs` 자동 생성 |
| Queue | BullMQ | 5.x | 비동기 스캔 Job 처리 (Redis 기반) |
| Rate Limiting | @nestjs/throttler | 5.x | API 요청 제한 |
| Scheduler | @nestjs/schedule | 4.x | StuckScanRecoveryTask Cron 스케줄러 |
| Logging | NestJS built-in Logger | - | 개발: debug, 운영: info |
| Testing | Jest + Supertest + @testcontainers/postgresql | - | 단위/통합 테스트 |

> **Redis 용도:** Phase 1부터 Redis를 도입하여 (1) BullMQ Job Queue, (2) express-session 세션 스토어로 사용한다. 범용 캐싱(node-cache → Redis 전환)은 Phase 2에서 진행한다.

### 2.3 Frontend (apps/web)

| 항목 | 선택 | 버전 |
|------|------|------|
| Framework | React | 18.x |
| Language | TypeScript | 5.x |
| Build | Vite | 5.x |
| UI Library | shadcn/ui + Tailwind CSS | shadcn/ui 2.x + Tailwind CSS 3.4.x |
| Server State | TanStack Query | 5.x |
| Client State | Zustand | 4.x |
| HTTP Client | Axios (shared instance) | 1.x |
| Router | React Router | 6.x |
| Charts | Recharts | 2.x |

### 2.4 AI 서버 (apps/ai, 선택 통합)

| 항목 | 선택 | 버전 |
|------|------|------|
| Framework | FastAPI | 0.115.x |
| Language | Python | 3.11+ |
| ASGI | Uvicorn | 0.32.x |
| HTTP Client | httpx | 0.27.x |

### 2.5 Infrastructure (로컬 개발)

```yaml
services:
  - PostgreSQL 16
  - Redis 7      # BullMQ 큐 + 세션 스토어
  - AI Server    # 선택 통합
```

---

## 3. 시스템 아키텍처

```text
┌──────────────────────────────────────────────────────────────┐
│                    Browser (React SPA)                        │
│              apps/web — TypeScript + React                    │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / REST
                            │ shared types: packages/shared
┌───────────────────────────▼──────────────────────────────────┐
│                  NestJS API Server (apps/api)                  │
│                                                               │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────────────┐  │
│  │ AuthModule  │  │  RepoModule │  │  DashboardModule     │  │
│  │ (Passport)  │  │             │  │                      │  │
│  └─────┬──────┘  └──────┬──────┘  └──────────┬───────────┘  │
│        │                │                     │              │
│  ┌─────▼────────────────▼─────────────────────▼──────────┐  │
│  │                   ScanModule                            │  │
│  │   ScanController → ScanService → ScanProcessor         │  │
│  └─────────────────────────┬──────────────────────────────┘  │
│                            │                                  │
│              ┌─────────────▼──────────────┐                  │
│              │       BullMQ Queue          │                  │
│              │    (scan-jobs queue)        │                  │
│              └─────────────┬──────────────┘                  │
│                            │                                  │
│        ┌───────────────────▼─────────────────────┐           │
│        │            ScanProcessor (Worker)         │           │
│        │  IGitProviderClient → IAnalysisApiClient │           │
│        │         → PrismaService (저장)            │           │
│        └───────────────────────────────────────────┘          │
└──────────┬───────────────────────┬───────────────────────────┘
           │                       │
┌──────────┴──────────┐   ┌───────┴───────────────────────────┐
│                     │   │  Analysis Backend                  │
│  ┌─────────────┐    │   │  - MockAnalysisApiClient (기본)    │
│  │ PostgreSQL   │    │   │  - InternalAnalysisApiClient      │
│  │  (Prisma)    │    │   │    → apps/ai FastAPI (선택 통합)  │
│  └─────────────┘    │   └───────────────────────────────────┘
│                     │
│  ┌─────────────┐    │
│  │ Redis 7      │    │
│  │ (Queue+세션) │    │
│  └─────────────┘    │
└─────────────────────┘
```

### 3.1 핵심 설계 원칙

1. **분석 시스템 분리:** `IAnalysisApiClient` 인터페이스를 통해서만 분석을 요청한다. Phase 1 기본값은 `MockAnalysisApiClient`이며, `MockAnalysisApiClient` → `InternalAnalysisApiClient` 교체 시 코드 변경 없이 환경변수 전환으로 처리한다.
2. **Consensus 데이터 모델 보존:** 단일 모델 결과만 저장하는 구조가 아니라, `consensusScore` 및 `modelResults`를 저장할 수 있는 데이터 구조를 유지한다.
3. **언어 확장 플러그인 구조:** `ILanguageHandler` 인터페이스 → `JavaLanguageHandler`. 새 언어 추가 시 구현체만 추가한다.
4. **스캔 비동기 처리:** `POST /api/scans`는 즉시 `scanId`를 반환하고, 실제 처리는 BullMQ Worker가 수행한다.
5. **Phase 2 확장 예약:** GitHub Webhook 기반 PR 자동 트리거와 Suggested Changes는 문서에 설계만 포함하고, MVP 구현 범위와 구분한다.
6. **타입 공유:** `packages/shared`의 타입을 API 응답 타입과 React 컴포넌트가 동시에 import한다.
7. **CORS 명시 설정:** `FRONTEND_URL` 환경변수로 허용 origin을 관리한다.
8. **Health Check 제공:** `GET /api/health` 엔드포인트로 API 서버 uptime과 DB/Redis 상태를 확인한다.

### 3.2 스캔 플로우 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant U as Browser
    participant API as NestJS API
    participant Q as BullMQ Queue
    participant W as ScanProcessor (Worker)
    participant Git as GitHub/GitLab API
    participant AI as IAnalysisApiClient
    participant DB as PostgreSQL

    U->>API: POST /api/scans { repoId, branch }
    API->>DB: 트랜잭션: 중복 체크 + Scan(PENDING) 생성
    API->>Q: Job 등록 (scanId)
    API-->>U: 202 { scanId, status: PENDING }

    U->>API: GET /api/scans/:scanId (3초 폴링)
    API-->>U: { status: PENDING }

    Q->>W: Job 실행
    W->>DB: Scan → RUNNING
    W->>Git: getLatestCommitSha()
    Git-->>W: commitSha
    W->>AI: analyze({ scanId, cloneUrl, branch, ... })
    AI-->>W: AnalysisResult { vulnerabilities[] }
    W->>DB: Vulnerability.createMany()
    W->>DB: Scan → DONE + 집계 저장

    U->>API: GET /api/scans/:scanId (폴링)
    API-->>U: { status: DONE, summary: { ... } }
    U->>API: GET /api/scans/:scanId/vulnerabilities
    API-->>U: PageResponse<VulnerabilityListItem>
```

### 3.3 OAuth 인증 플로우 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant U as Browser
    participant API as NestJS API
    participant GH as GitHub OAuth
    participant DB as PostgreSQL
    participant Redis as Redis (Session)

    U->>API: GET /api/auth/github
    API->>GH: OAuth 리다이렉트 (state 포함)
    GH->>U: GitHub 로그인 페이지
    U->>GH: 사용자 인증 + 권한 동의
    GH->>API: GET /api/auth/github/callback?code=xxx&state=yyy
    API->>GH: code → accessToken 교환
    GH-->>API: accessToken
    API->>DB: User upsert + OAuthToken 저장 (AES-256-GCM 암호화)
    API->>Redis: 세션 저장 (userId)
    API-->>U: Set-Cookie: connect.sid → Redirect FRONTEND_URL/dashboard
```

---

## 4. Monorepo 디렉토리 구조

### 4.1 루트

```text
Aegisai/
├── package.json              # pnpm workspace 루트
├── pnpm-workspace.yaml
├── .npmrc                    # engine-strict=true
├── docker-compose.yml
├── .env.example
├── apps/
│   ├── api/                  # NestJS 백엔드
│   ├── web/                  # React 프론트엔드
│   └── ai/                   # FastAPI AI 추론 서버 (선택 통합)
└── packages/
    └── shared/               # 공유 타입 패키지
        ├── package.json      # name: @aegisai/shared
        ├── tsconfig.json
        └── src/
            ├── index.ts
            └── types/
                ├── common.ts          # ApiResponse, SuccessResponse, PageResponse, ErrorResponse
                ├── auth.ts
                ├── repo.ts
                ├── scan.ts            # ScanStatus enum, ScanSummary
                ├── vulnerability.ts   # Severity enum, VulnStatus enum, VulnerabilityDetail
                └── dashboard.ts
```

### 4.2 Backend (apps/api)

```text
apps/api/
├── package.json              # package.json name: @aegisai/api
├── tsconfig.json
├── nest-cli.json
├── prisma/
│   ├── schema.prisma
│   ├── seed.ts
│   └── migrations/
│
└── src/
    ├── main.ts               # NestJS 부트스트랩
    ├── app.module.ts         # 루트 모듈
    │
    ├── config/
    │   ├── config.module.ts  # NestJS @nestjs/config ConfigModule의 래퍼 — 환경 변수 유효성 검사 및 타입 안전 접근 제공
    │   └── config.service.ts
    │
    ├── prisma/
    │   ├── prisma.module.ts
    │   └── prisma.service.ts
    │
    ├── auth/
    │   ├── auth.module.ts
    │   ├── auth.controller.ts
    │   ├── auth.service.ts
    │   ├── auth.serializer.ts        # Passport 세션 serializer/deserializer ⚠️ 필수
    │   ├── strategies/
    │   │   ├── github.strategy.ts
    │   │   └── gitlab.strategy.ts
    │   ├── guards/
    │   │   └── session-auth.guard.ts
    │   ├── decorators/
    │   │   └── current-user.decorator.ts
    │   └── utils/
    │       └── token-crypto.util.ts  # AES-256-GCM 암/복호화
    │
    ├── repo/
    │   ├── repo.module.ts
    │   ├── repo.controller.ts
    │   └── repo.service.ts
    │
    ├── scan/
    │   ├── scan.module.ts
    │   ├── scan.controller.ts
    │   ├── scan.service.ts
    │   ├── scan.processor.ts
    │   └── stuck-scan-recovery.task.ts  # RUNNING 상태 타임아웃 복구 스케줄러
    │
    ├── webhook/               # Phase 2 예약
    │   ├── webhook.module.ts
    │   └── webhook.controller.ts
    │
    ├── vulnerability/
    │   ├── vulnerability.module.ts
    │   ├── vulnerability.controller.ts
    │   └── vulnerability.service.ts
    │
    ├── dashboard/
    │   ├── dashboard.module.ts
    │   ├── dashboard.controller.ts
    │   └── dashboard.service.ts
    │
    ├── client/
    │   ├── analysis/
    │   │   ├── analysis-api-client.interface.ts
    │   │   ├── analysis-api.dto.ts             # NestJS class-validator DTO: AnalysisRequest/Result의 런타임 검증용 클래스
    │   │   ├── mock-analysis-api.client.ts
    │   │   ├── internal-analysis-api.client.ts   # 선택 통합
    │   │   └── analysis-api.module.ts
    │   │
    │   └── git/
    │       ├── git-provider-client.interface.ts
    │       ├── github.client.ts
    │       ├── gitlab.client.ts
    │       ├── git-client.registry.ts
    │       └── git-client.module.ts
    │
    ├── language/
    │   ├── language-handler.interface.ts
    │   ├── language-handler.registry.ts
    │   └── handlers/
    │       └── java.language-handler.ts
    │
    ├── health/
    │   ├── health.module.ts
    │   └── health.controller.ts
    │
    └── common/
        ├── dto/
        │   ├── api-response.dto.ts
        │   └── pagination.dto.ts
        ├── decorators/
        │   ├── raw-body.decorator.ts
        │   ├── resource-owner-check.decorator.ts
        │   └── skip-transform.decorator.ts
        ├── filters/
        │   └── global-exception.filter.ts
        ├── guards/
        │   ├── resource-owner.guard.ts
        │   └── session-aware-throttler.guard.ts
        └── interceptors/
            └── response-transform.interceptor.ts
```

#### app.module.ts — 루트 모듈 전체 구성

```typescript
// apps/api/src/app.module.ts
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_INTERCEPTOR, APP_GUARD } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule } from './config/config.module';
import { ConfigService } from './config/config.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { RepoModule } from './repo/repo.module';
import { ScanModule } from './scan/scan.module';
import { VulnerabilityModule } from './vulnerability/vulnerability.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { HealthModule } from './health/health.module';
import { LanguageModule } from './language/language.module';
import { ScheduleModule } from '@nestjs/schedule';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { ResponseTransformInterceptor } from './common/interceptors/response-transform.interceptor';
import { SessionAwareThrottlerGuard } from './common/guards/session-aware-throttler.guard';

@Module({
  imports: [
    // 1. Config — 환경변수 유효성 검사 (가장 먼저 로드)
    ConfigModule,

    // 2. BullMQ — Redis 연결 (비동기 설정)
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        connection: {
          url: config.get('REDIS_URL'),
        },
      }),
      inject: [ConfigService],
    }),

    // 3. Rate Limiting
    ThrottlerModule.forRoot([
      { name: 'default', ttl: 60000, limit: 100 },    // 인증 사용자 기본
      { name: 'unauthenticated', ttl: 60000, limit: 20 },
      { name: 'scan', ttl: 60000, limit: 10 },          // POST /api/scans 전용
    ]),

    // 4. 인프라 모듈
    PrismaModule,

    // 5. 도메인 모듈
    AuthModule,
    RepoModule,
    ScanModule,
    VulnerabilityModule,
    DashboardModule,
    LanguageModule,

    // 6. 유틸리티 모듈
    HealthModule,
    ScheduleModule.forRoot(),  // StuckScanRecoveryTask Cron 스케줄러

    // 7. Phase 2 예약
    // WebhookModule은 Phase 2에서만 추가한다.
    // import { WebhookModule } from './webhook/webhook.module';
    // WebhookModule,
  ],
  providers: [
    // 글로벌 예외 필터
    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
    // 글로벌 응답 래핑 인터셉터
    { provide: APP_INTERCEPTOR, useClass: ResponseTransformInterceptor },
    // 글로벌 Rate Limiting 가드
    { provide: APP_GUARD, useClass: SessionAwareThrottlerGuard },
  ],
})
export class AppModule {}
```

### 4.3 Frontend (apps/web)

```text
apps/web/
├── package.json              # package.json name: @aegisai/web
├── vite.config.ts
├── tailwind.config.ts
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── router.tsx
    │
    ├── pages/
    │   ├── LoginPage.tsx
    │   ├── DashboardPage.tsx
    │   ├── ReposPage.tsx
    │   ├── ScanPage.tsx
    │   ├── VulnerabilitiesPage.tsx
    │   └── VulnerabilityDetailPage.tsx
    │
    ├── components/
    │   ├── layout/
    │   │   ├── AppShell.tsx
    │   │   └── Sidebar.tsx
    │   ├── dashboard/
    │   │   ├── SeverityPieChart.tsx
    │   │   ├── TrendLineChart.tsx
    │   │   └── StatCard.tsx
    │   ├── scan/
    │   │   ├── RepoSelector.tsx
    │   │   └── ScanStatusBadge.tsx
    │   └── vulnerability/
    │       ├── VulnCard.tsx
    │       ├── SeverityBadge.tsx
    │       ├── CodeDiffViewer.tsx
    │       ├── ConsensusScoreBadge.tsx  # consensusScore 시각화
    │       └── ModelResultsPanel.tsx    # 모델별 판단 근거 아코디언
    │
    ├── hooks/
    │   ├── useAuth.ts
    │   ├── useRepos.ts
    │   ├── useScan.ts
    │   └── useVulnerabilities.ts
    │
    ├── api/
    │   ├── client.ts          # Axios 인스턴스 + 인터셉터
    │   ├── auth.ts
    │   ├── repos.ts
    │   ├── scans.ts
    │   ├── vulnerabilities.ts
    │   └── dashboard.ts
    │
    └── store/
        └── auth.store.ts      # Zustand — 인증 상태
```

### 4.4 AI 서버 (apps/ai, 선택 통합)

```text
apps/ai/
├── main.py                   # FastAPI 앱 진입점 (포트: 8000)
├── requirements.txt
├── Dockerfile                # ⚠️ git 패키지 설치 필수
├── .env
│
├── routers/
│   ├── analyze.py            # POST /analyze
│   └── health.py             # GET /health
│
├── models/
│   ├── base.py               # IVulnDetector 추상 클래스
│   ├── finetuned_a.py
│   ├── finetuned_b.py
│   └── registry.py
│
├── consensus/
│   └── engine.py             # consensusScore 계산
│
├── schemas/
│   ├── request.py            # AnalyzeRequest Pydantic 모델
│   └── response.py           # AnalyzeResponse Pydantic 모델
│
└── training/                 # 배포 이미지에서 제외
    ├── dataset/
    ├── finetune.py
    └── evaluate.py
```

> **원칙:**
> - `apps/ai`는 선택 통합 경로이며, Phase 1 완료의 필수 조건이 아니다.
> - Dockerfile 작성 시 `RUN apt-get update && apt-get install -y git`를 반드시 포함한다.
> - `training/`은 배포 이미지에 포함하지 않는다.
> - `schemas/`의 필드명·타입은 NestJS 측 타입과 1:1로 맞춘다.

### 4.5 packages/shared 설정

#### packages/shared/package.json

```json
// packages/shared/package.json
{
  "name": "@aegisai/shared",
  "version": "0.0.1",
  "private": true,
  "main": "./src/index.ts",
  "types": "./src/index.ts",
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch"
  },
  "devDependencies": {
    "typescript": "^5.x"
  }
}
```

#### packages/shared/tsconfig.json

```json
// packages/shared/tsconfig.json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src"]
}
```

> **⚠️ moduleResolution 호환성 주의:** `"moduleResolution": "bundler"`는 Vite(apps/web)와는 호환되나, NestJS(apps/api)는 일반적으로 `"node16"` 또는 `"node"` 모드를 사용한다. apps/api에서 `@aegisai/shared`를 tsconfig paths로 직접 소스 참조할 경우 문제가 없지만, 빌드된 `.d.ts`를 참조하는 경우 module resolution 불일치가 발생할 수 있다. 이상이 생기면 shared의 `moduleResolution`을 `"node16"`으로 변경하고 apps/web의 vite.config.ts에서 별도 alias를 설정한다.

#### apps/api/package.json 및 apps/web/package.json — 공유 타입 참조

두 패키지의 `dependencies`에 각각 추가:

```json
"dependencies": {
  "@aegisai/shared": "workspace:*"
}
```

#### apps/api/tsconfig.json — paths 설정

```json
{
  "compilerOptions": {
    "paths": {
      "@aegisai/shared": ["../../packages/shared/src"],
      "@aegisai/shared/*": ["../../packages/shared/src/*"]
    }
  }
}
```

> **개발 모드:** `tsconfig references` 또는 path alias 를 통해 `packages/shared/src` 소스를 직접 참조하므로, 개발 중에는 별도 빌드 없이 변경이 실시간 반영된다. **배포 빌드** 시에는 `pnpm --filter @aegisai/shared build`로 `.d.ts` + `.js`를 먼저 생성한다.

---

## 5. Prisma 스키마

```prisma
// apps/api/prisma/schema.prisma

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
  accessToken    String       // AES-256-GCM 암호화 저장 (키: TOKEN_ENCRYPTION_KEY)
  refreshToken   String?      // MVP: 미사용, Phase 2에서 자동 갱신 구현
  expiresAt      DateTime?
  createdAt      DateTime     @default(now())
  updatedAt      DateTime     @updatedAt

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([userId, provider])
  @@unique([provider, providerUserId])
}

model ConnectedRepo {
  id             String       @id @default(uuid())
  userId         String
  provider       RepoProvider
  providerRepoId String       // GitHub/GitLab의 레포 고유 ID (문자열로 저장 — int/string 타입 차이 흡수)
  fullName       String       // "owner/repo-name"
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
  @@index([createdAt(sort: Desc)]) // Prisma 5.x에서 PostgreSQL provider일 때만 지원
}

model Vulnerability {
  id             String        @id @default(uuid())
  scanId         String
  title          String
  description    String
  severity       Severity
  filePath       String
  lineStart      Int
  lineEnd        Int?
  codeSnippet    String?
  fixSuggestion  String?       // unified diff 형식
  fixExplanation String?       // 한국어 설명
  cweId          String?
  cveId          String?
  owaspCategory  String?
  referenceLinks Json?         // [{ title: string, url: string }]
  consensusScore Float?        // 0.0~1.0 — AI 모델 간 합의 신뢰도
  modelResults   Json?         // [{ model, detected, severity, reasoning }]
  status         VulnStatus    @default(OPEN)
  userFeedback   UserFeedback?
  createdAt      DateTime      @default(now())
  updatedAt      DateTime      @updatedAt

  scan Scan @relation(fields: [scanId], references: [id], onDelete: Cascade)

  @@index([scanId])
  @@index([severity])
  @@index([status])
}
```

### 5.1 스키마 설계 주의사항

- `provider` 필드는 `String` 대신 `RepoProvider` enum을 사용하여 DB 레벨에서 타입 안전성을 보장한다.
- `providerRepoId`는 GitHub(숫자)와 GitLab(숫자/문자 혼용)의 ID 타입 차이를 흡수하기 위해 문자열로 저장한다.
- `Scan.language`는 확장성을 위해 문자열로 유지하되, 애플리케이션 레벨에서는 `LanguageHandlerRegistry`에 등록된 언어만 허용한다.
- **동일 `ConnectedRepo`에 대해 동시에 하나의 활성 스캔만 허용하는 정책은 서비스 + DB 락 기반 규칙이다.** DB 스키마에 단순 유니크 제약을 두지는 않지만, `ScanService.requestScan()`에서 PostgreSQL advisory lock(예: `pg_advisory_xact_lock`) 또는 동등한 직렬화 메커니즘을 사용해 경쟁 상태를 차단해야 한다. 단순 `findFirst()` 후 `create()`만으로는 보장되지 않는다.
- `userFeedback`는 사용자 판단 데이터를 보존하기 위한 필드이며, `status`는 최종 취약점 처리 상태를 나타낸다. MVP에서는 `PATCH /feedback` 호출 시 `feedback=ACCEPTED`이면 `status=ACCEPTED`, `feedback=REJECTED`이면 `status=REJECTED`로 동기화한다.
- 필드명 `referenceLinks`는 API 응답 타입과 일치시킨다 (`references`로 혼용하지 않는다).
- **API 레이어에서는 provider 값을 소문자('github', 'gitlab')로 주고받고, DB 저장 시 Prisma enum 대문자(GITHUB, GITLAB)로 변환한다. 변환은 Service 레이어에서 처리한다.**
- `@@unique([userId, provider])` 제약으로 한 사용자당 provider별 토큰은 하나만 유지된다. 동일 provider 재인증 시 기존 토큰을 upsert로 갱신한다 (AuthService.findOrCreateUser 내부에서 처리).
- **`TOKEN_ENCRYPTION_KEY` 로테이션:** MVP에서는 단일 키를 사용한다. 키 교체가 필요한 경우를 대비하여 `OAuthToken` 레코드에 암호화 키 버전을 식별하는 확장 경로를 고려한다. 예: 암호화된 토큰 앞에 키 버전 프리픽스를 붙이는 방식 (`v1:<encrypted>`) 또는 별도 `keyVersion` 컬럼 추가. Phase 2에서 키 로테이션 전략을 정식으로 구현한다.
- **`Scan` 비정규화 필드 동기화:** `Scan` 모델의 `vulnCritical`, `vulnHigh`, `vulnMedium`, `vulnLow`, `vulnInfo` 필드는 성능 최적화를 위한 비정규화 캐시이다. 이 값은 `ScanProcessor`가 스캔 완료 시 일회성으로 계산하여 저장한다. MVP에서는 취약점의 `status` 변경(OPEN→FIXED 등)이나 `userFeedback` 변경 시 이 비정규화 필드를 재계산하지 않는다. 대시보드의 `openVulnerabilities` 집계는 `Vulnerability` 테이블에서 직접 쿼리한다. Phase 2에서 취약점 상태 변경 시 `Scan` 비정규화 필드를 동기화하는 이벤트 기반 로직(또는 DB 트리거)을 도입한다.

### 5.2 ERD

```mermaid
erDiagram
    User {
        uuid id PK
        string email UK
        string name
        string avatarUrl
        datetime createdAt
        datetime updatedAt
    }
    OAuthToken {
        uuid id PK
        uuid userId FK
        RepoProvider provider
        string providerUserId
        string accessToken "AES-256-GCM 암호화"
        string refreshToken
        datetime expiresAt
        datetime createdAt
        datetime updatedAt
    }
    ConnectedRepo {
        uuid id PK
        uuid userId FK
        RepoProvider provider
        string providerRepoId
        string fullName "owner/repo-name"
        string cloneUrl
        string defaultBranch
        boolean isPrivate
        datetime connectedAt
        datetime updatedAt
    }
    Scan {
        uuid id PK
        uuid connectedRepoId FK
        string branch
        string commitSha
        ScanStatus status
        string language
        int totalFiles
        int totalLines
        int vulnCritical
        int vulnHigh
        int vulnMedium
        int vulnLow
        int vulnInfo
        string errorMessage
        datetime startedAt
        datetime completedAt
        datetime createdAt
        datetime updatedAt
    }
    Vulnerability {
        uuid id PK
        uuid scanId FK
        string title
        string description
        Severity severity
        string filePath
        int lineStart
        int lineEnd
        string codeSnippet
        string fixSuggestion "unified diff"
        string fixExplanation
        string cweId
        string cveId
        string owaspCategory
        json referenceLinks
        float consensusScore "0.0~1.0"
        json modelResults
        VulnStatus status
        UserFeedback userFeedback
        datetime createdAt
        datetime updatedAt
    }

    User ||--o{ OAuthToken : "has (1 per provider)"
    User ||--o{ ConnectedRepo : "connects"
    ConnectedRepo ||--o{ Scan : "triggers"
    Scan ||--o{ Vulnerability : "discovers"
```

---

## 6. API 명세 (MVP)

### 6.1 공통 규칙

- Base URL: `/api`
- 인증: Session Cookie (`connect.sid`) — Passport.js 세션
  - 세션 TTL: **24시간** (`maxAge: 86400000`)
  - `cookie.secure`: production에서만 `true`
  - `cookie.sameSite`: `'lax'`
  - `cookie.httpOnly`: `true`
- 페이지네이션 기본값: `page=1`, `size=20`, **최대 size=100**
- 모든 JSON 응답은 기본적으로 `ApiResponse<T>` 래퍼 사용
- **아래 API 예시의 JSON 본문은 모두 `data` 내부 payload만 표기한다.** 실제 wire response는 `ResponseTransformInterceptor`에 의해 `{ success, data, message, timestamp }` 형태로 감싸진다.
- 예외: `GET /api/health`는 로드밸런서/오케스트레이터 호환을 위해 `@SkipTransform()`을 적용한 raw JSON 응답을 사용한다.

**CSRF 보호 전략:**

`sameSite: 'lax'`는 GET 요청의 크로스사이트 전송만 허용하므로 대부분의 CSRF 공격을 방지하지만, state-changing POST/PATCH/DELETE 엔드포인트에 대한 추가 보호를 위해 **커스텀 헤더 검증** 방식을 적용한다.

- 프론트엔드 Axios 인스턴스에서 모든 요청에 `X-Requested-With: XMLHttpRequest` 헤더를 포함한다.
- 백엔드 `SessionAuthGuard`에서 POST/PATCH/DELETE 요청 시 `X-Requested-With` 헤더 존재를 검증한다. 누락 시 403 반환.
- 이 방식은 브라우저의 CORS preflight 메커니즘과 결합하여 크로스사이트 요청 위조를 방지한다.

```typescript
// packages/shared/src/types/common.ts
export interface SuccessResponse<T> {
  success: true;
  data: T;
  message: string | null;
  timestamp: string;
}

export interface ErrorResponse {
  success: false;
  data: null;
  message: string;
  errorCode: string;        // e.g. "SCAN_ALREADY_RUNNING", "UNAUTHORIZED"
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
// 200 - ApiResponse<AuthUser>. 아래는 data payload 예시
{
  id: string;
  email: string | null;
  name: string;
  avatarUrl: string | null;
  connectedProviders: ('github' | 'gitlab')[];
}
// 401 — 미인증
```

#### `POST /api/auth/logout`

```typescript
null  // 200 OK — ApiResponse<null>의 data payload
```

```typescript
// packages/shared/src/types/auth.ts
export interface AuthUser {
  id: string;
  email: string | null;
  name: string;
  avatarUrl: string | null;
  connectedProviders: ('github' | 'gitlab')[];
}
```

#### OAuth2 플로우

```text
GET /api/auth/github          → GitHub OAuth 시작
GET /api/auth/github/callback → GitHub 콜백 (Passport 처리)
GET /api/auth/gitlab          → GitLab OAuth 시작
GET /api/auth/gitlab/callback → GitLab 콜백 (Passport 처리)
// 성공 시 → FRONTEND_URL/dashboard 로 리다이렉트
```

### 6.3 레포지토리

#### `GET /api/repos`

// 현재 사용자의 전체 연동 레포를 배열로 반환한다. 연동 레포 수가 제한적이므로 별도 페이지네이션을 적용하지 않는다.
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

> **구현 힌트:** `lastScanAt`과 `lastScanStatus`는 `ConnectedRepo`에 대한 가장 최근 Scan 레코드에서 파생한다. Prisma 쿼리 예시:
> ```typescript
> const repos = await this.prisma.connectedRepo.findMany({
>   where: { userId },
>   include: {
>     scans: {
>       orderBy: { createdAt: 'desc' },
>       take: 1,
>       select: { completedAt: true, status: true },
>     },
>   },
> });
> // 각 repo에 대해:
> // lastScanAt = repo.scans[0]?.completedAt ?? null
> // lastScanStatus = repo.scans[0]?.status ?? null
> ```

#### `GET /api/repos/available?provider=github&page=1&size=30`

- 응답 TTL 5분 캐시 (`node-cache`)
- 외부 Git provider API pagination을 내부 API pagination과 매핑한다.
- **캐시 키 전략:** `repos-available:${userId}:${provider}:${page}:${size}` — 사용자별 + provider별 + 페이지별로 캐시를 분리한다. 새 레포 연동(`POST /api/repos`) 또는 레포 해제(`DELETE /api/repos/:repoId`) 시 해당 사용자의 available 캐시를 전부 무효화한다.
- **캐시 무효화 구현:** `node-cache`는 prefix 기반 일괄 삭제 API가 없으므로 `cache.keys()`로 전체 키를 조회한 후 prefix가 `repos-available:${userId}:`인 키를 필터링하여 `cache.del(keys)`로 삭제한다:
  ```typescript
  const prefix = `repos-available:${userId}:`;
  const keysToDelete = this.cache.keys().filter(k => k.startsWith(prefix));
  this.cache.del(keysToDelete);
  ```

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
// Request
{
  provider: 'github' | 'gitlab';
  providerRepoId: string;
}
// Response 201 - ApiResponse<ConnectedRepoSummary>. 아래는 data payload 예시
{ id: string; fullName: string; connectedAt: string; }
```

> 서버는 `providerRepoId`와 `provider`를 기준으로 Git Provider API에서 레포 메타데이터(`fullName`, `cloneUrl`, `defaultBranch`, `isPrivate`)를 직접 조회하여 DB에 저장한다. 클라이언트가 전송한 메타데이터는 수신하지 않는다.
>
> 응답 코드:
> ```
> // 400 — provider/providerRepoId 등 필수 필드 누락 또는 유효성 검사 실패
> // 404 — Git Provider API에서 해당 레포를 찾을 수 없음 (권한 부족 또는 삭제됨)
> // 409 — 이미 동일 사용자가 동일 provider + providerRepoId로 연동한 레포가 존재
> ```

#### `DELETE /api/repos/:repoId`

```typescript
null  // 204 No Content
// ⚠️ @HttpCode(204)와 @SkipTransform()을 함께 적용하여 ResponseTransformInterceptor 래핑을 제외한다.
// Controller 예시:
// @Delete(':repoId')
// @HttpCode(204)
// @SkipTransform()
// @UseGuards(SessionAuthGuard)
// async deleteRepo(@Param('repoId') repoId: string, @CurrentUser() user: AuthUser) { ... }
```

```typescript
// packages/shared/src/types/repo.ts
import type { ScanStatus } from './scan';

export interface ConnectedRepoItem {
  id: string;
  provider: 'github' | 'gitlab';
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  lastScanAt: string | null;
  lastScanStatus: ScanStatus | null;
}

export interface AvailableRepoItem {
  providerRepoId: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  isPrivate: boolean;
  alreadyConnected: boolean;
}

export interface ConnectRepoRequest {
  provider: 'github' | 'gitlab';
  providerRepoId: string;
}

export interface ConnectRepoResponse {
  id: string;
  fullName: string;
  connectedAt: string;
}
```

### 6.4 스캔

#### `POST /api/scans` — 즉시 반환, BullMQ 비동기 처리

> Controller에서 `@HttpCode(202)` 데코레이터를 명시하여 ResponseTransformInterceptor가 래핑하더라도 HTTP 202를 유지한다.

```typescript
// Request
{ repoId: string; branch: string; }

// Response 202
{
  scanId: string;
  status: 'PENDING';
  message: string;
}
// 409 — 동일 레포에 PENDING 또는 RUNNING 스캔 존재 시
```

#### `GET /api/scans/:scanId` — 스캔 상태 폴링

> 인증 필수. 요청자가 해당 스캔의 ConnectedRepo 소유자인지 Scan → ConnectedRepo → User 경로로 검증한다.

**프론트엔드 폴링 설정:**
- 폴링 간격: **3초**
- 최대 폴링 시간: **10분** (3초 × 200회 = 600초, 이후 자동 중단 + "스캔이 예상보다 오래 걸리고 있습니다" 메시지 표시)
- TanStack Query `refetchInterval` 사용, `DONE` 또는 `FAILED` 상태 수신 시 `refetchInterval: false`로 전환하여 폴링 중단
- 앱 레벨 스캔 타임아웃(5분)과 stuck scan 복구 지연을 고려해 10분까지 폴링한다. BullMQ 자체 옵션만으로는 전체 실행 시간 제한이 보장되지 않으므로, 실제 타임아웃 판정은 `ScanProcessor`와 `StuckScanRecoveryTask`가 담당한다.

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
    critical: number; high: number; medium: number;
    low: number; info: number;
  };
  startedAt: string | null;
  completedAt: string | null;
  errorMessage: string | null;
  createdAt: string;
}
```

```typescript
/** packages/shared/src/types/scan.ts */
export type ScanStatus = 'PENDING' | 'RUNNING' | 'DONE' | 'FAILED';

export interface ScanSummary {
  id: string;
  repoFullName: string;
  branch: string;
  commitSha: string | null;
  status: ScanStatus;
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
  createdAt: string;
}

export interface ScanRequestBody {
  repoId: string;
  branch: string;
}

export interface ScanRequestResponse {
  scanId: string;
  status: 'PENDING';
  message: string;
}
```

#### `GET /api/repos/:repoId/scans?page=1&size=10`

> 인증 필수. 요청자가 해당 ConnectedRepo의 소유자인지 검증한다.
>
> 정렬: `createdAt:desc` 고정 (최신 스캔 우선)
>
> 응답 코드:
> ```
> // 200 — ApiResponse<PageResponse<ScanSummary>>
> // 401 — 미인증
> // 404 — 해당 레포가 없거나 접근 권한 없음
> ```

```typescript
PageResponse<ScanSummary>
```

### 6.5 취약점

#### `GET /api/scans/:scanId/vulnerabilities`

> 인증 필수. 요청자가 해당 스캔의 ConnectedRepo 소유자인지 Scan → ConnectedRepo → User 경로로 검증한다.

지원 쿼리 파라미터:
- `severity=HIGH&severity=LOW` (다중 선택)
- `status=OPEN`
- `page=1`, `size=20`
- `sort=createdAt:desc` 또는 `sort=severity:asc` (severity 정렬은 `CRITICAL(1) > HIGH(2) > MEDIUM(3) > LOW(4) > INFO(5)` 커스텀 순서를 적용한다 — 알파벳순이 아님)

  **Severity 커스텀 정렬 구현:** Prisma는 enum 커스텀 정렬을 직접 지원하지 않으므로, **Prisma `$queryRaw`를 사용한 SQL `CASE WHEN` 구문**으로 구현한다.
  ```sql
  ORDER BY CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
    WHEN 'INFO' THEN 5
  END ASC
  ```
  또는 서비스 레이어에서 Prisma 결과를 가져온 후 `SEVERITY_ORDER` 상수 맵을 사용한 인메모리 정렬을 적용할 수 있다 (데이터량이 적은 MVP에서 유효).

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

> 인증 필수. 요청자가 해당 취약점이 속한 스캔의 ConnectedRepo 소유자인지 Scan → ConnectedRepo → User 경로로 검증한다.

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
  fixSuggestion: string | null;   // unified diff
  fixExplanation: string | null;  // 한국어 설명
  cweId: string | null;
  cveId: string | null;
  owaspCategory: string | null;
  referenceLinks: { title: string; url: string; }[] | null;
  consensusScore: number | null;  // 0.0~1.0 AI 합의 신뢰도
  modelResults: {                 // 모델별 분석 근거 (consensusScore < 1.0 시 UI에 표시)
    model: string;
    detected: boolean;
    severity: string;
    reasoning: string;
  }[] | null;
  status: 'OPEN' | 'FIXED' | 'ACCEPTED' | 'REJECTED';
  userFeedback: 'ACCEPTED' | 'REJECTED' | null;
}
```

```typescript
/** packages/shared/src/types/vulnerability.ts */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type VulnStatus = 'OPEN' | 'FIXED' | 'ACCEPTED' | 'REJECTED';
export type UserFeedback = 'ACCEPTED' | 'REJECTED';

export interface ModelResultView {
  model: string;
  detected: boolean;
  severity: string;
  reasoning: string;
}

export interface ReferenceLink {
  title: string;
  url: string;
}

export interface VulnerabilityListItem {
  id: string;
  title: string;
  severity: Severity;
  filePath: string;
  lineStart: number;
  lineEnd: number | null;
  cweId: string | null;
  owaspCategory: string | null;
  status: VulnStatus;
}

export interface VulnerabilityDetail {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  filePath: string;
  lineStart: number;
  lineEnd: number | null;
  codeSnippet: string | null;
  fixSuggestion: string | null;
  fixExplanation: string | null;
  cweId: string | null;
  cveId: string | null;
  owaspCategory: string | null;
  referenceLinks: ReferenceLink[] | null;
  consensusScore: number | null;
  modelResults: ModelResultView[] | null;
  status: VulnStatus;
  userFeedback: UserFeedback | null;
}

export interface VulnerabilityFeedbackRequest {
  feedback: UserFeedback;
}

export interface VulnerabilityFeedbackResponse {
  id: string;
  status: VulnStatus;
  userFeedback: UserFeedback;
}
```

#### `PATCH /api/vulnerabilities/:vulnId/feedback`

> 인증 필수. 해당 취약점이 속한 스캔의 ConnectedRepo 소유자만 피드백할 수 있다.

```typescript
// Request
{ feedback: 'ACCEPTED' | 'REJECTED' }
// Response
{ id: string; status: 'ACCEPTED' | 'REJECTED'; userFeedback: 'ACCEPTED' | 'REJECTED'; }
```

### 6.6 대시보드

#### `GET /api/dashboard`

```typescript
{
  totalRepos: number;
  totalScans: number;
  openVulnerabilities: {
    critical: number; high: number; medium: number; low: number; info: number;
  };
  recentScans: ScanSummary[];   // 최근 5건
  trend: {
    date: string;               // "2026-03-08"
    critical: number; high: number; medium: number;
    // MEDIUM 이상 심각도만 추이를 추적한다 (LOW, INFO는 노이즈 방지를 위해 제외)
  }[];                          // 최근 30일
}
```

```typescript
// packages/shared/src/types/dashboard.ts
import type { ScanSummary } from './scan';

export interface TrendItem {
  date: string;       // "2026-03-08"
  critical: number;
  high: number;
  medium: number;
}

export interface DashboardData {
  totalRepos: number;
  totalScans: number;
  openVulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recentScans: ScanSummary[];   // 최근 5건
  trend: TrendItem[];            // 최근 30일
}
```

```typescript
// packages/shared/src/index.ts
export * from './types/common';
export * from './types/auth';
export * from './types/repo';
export * from './types/scan';
export * from './types/vulnerability';
export * from './types/dashboard';
```

**대시보드 집계 쿼리 캐싱 전략:**
- **Phase 1에서도 다음 캐싱 최적화를 적용한다:**
  - `node-cache`로 대시보드 응답을 **TTL 1분** 캐싱
  - 캐시 키: `dashboard:${userId}` (사용자별 캐시)
  - 스캔 완료 시(`ScanProcessor` DONE 처리 후) 해당 사용자의 대시보드 캐시를 무효화한다
- 데이터가 더 증가하면 PostgreSQL Materialized View 또는 별도 집계 테이블 도입을 검토한다.

### 6.7 Health Check

#### `GET /api/health` — 인증 불필요

> `@SkipTransform()` 적용. 운영 헬스체커가 고정된 raw JSON 형태를 기대하므로 `ApiResponse<T>` 래퍼를 사용하지 않는다.

```typescript
{
  status: 'ok' | 'degraded';
  uptime: number;              // 초 단위
  services: {
    database: 'up' | 'down';
    redis: 'up' | 'down';
  };
  timestamp: string;
}
```

판정 규칙: DB와 Redis가 모두 `up`이면 `ok`, 하나라도 `down`이면 `degraded`.

### 6.8 Rate Limiting

- 인증 사용자: **100 req/min**, 미인증: **20 req/min**
- `POST /api/scans`: **10 req/min** (스캔 남용 방지)
- GitHub/GitLab API 호출: 토큰당 요청 횟수 추적, Rate Limit 도달 시 429 반환
- 구현: `@nestjs/throttler` 모듈 사용

**식별 기준:**
- 인증 사용자: **세션 ID 기반** (connect.sid 쿠키)
- 미인증 요청: **IP 기반** (`@nestjs/throttler`의 기본 동작 — `req.ip` 사용)
- `X-Forwarded-For` 헤더 신뢰 설정: 리버스 프록시 뒤에서 운영 시 `app.set('trust proxy', 1)` 설정을 `main.ts`에 추가해야 한다. 미설정 시 모든 요청이 프록시 IP로 식별되어 Rate Limiting이 의도대로 동작하지 않는다.
- 구현 시 `ThrottlerGuard`를 그대로 쓰지 않고, 인증 여부에 따라 `sessionID ?? req.ip`를 반환하는 커스텀 가드를 사용한다.
- `POST /api/scans`에는 `@Throttle({ scan: { limit: 10, ttl: 60000 } })`를 명시해 기본 한도와 별도 적용한다.

### 6.9 Phase 2 예약 API

#### `POST /api/vulnerabilities/:vulnId/suggest-change`

GitHub PR에 Suggested Changes 코멘트를 삽입한다.

```typescript
// Request
{ prNumber: number; repoFullName: string; }
// Response 201
{ commentId: string; htmlUrl: string; }
// 실패 조건: fixSuggestion 없음(400), GitHub API 오류(502)
```

---

## 7. Analysis API 명세

### 7.1 인터페이스 정의

```typescript
// client/analysis/analysis-api-client.interface.ts

export interface IAnalysisApiClient {
  /**
   * 레포지토리 코드 분석 요청.
   * Phase 1: MockAnalysisApiClient
   * 선택 통합: InternalAnalysisApiClient → apps/ai
   */
  analyze(request: AnalysisRequest, options?: { signal?: AbortSignal }): Promise<AnalysisResult>;
}

export interface AnalysisRequest {
  scanId: string;
  cloneUrl: string;
  branch: string;
  commitSha?: string;
  language: string;         // 현재 허용값은 "java"뿐이지만 인터페이스는 확장 가능
  accessToken: string;      // private 레포용 Git 토큰 (복호화된 값 전달)
}

/** 각 LLM 모델 하나의 분석 결과 */
export interface ModelResult {
  model: string;            // e.g. "claude-3-5-sonnet", "gemini-2.0-flash"
  detected: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reasoning: string;        // 모델의 판단 근거 (한국어)
}

export interface VulnerabilityItem {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  lineStart: number;
  lineEnd?: number;
  codeSnippet?: string;
  fixSuggestion?: string;     // unified diff 형식
  fixExplanation?: string;    // 한국어 설명
  cweId?: string;
  cveId?: string;
  owaspCategory?: string;
  referenceLinks?: { title: string; url: string }[];
  consensusScore: number;     // 응답 계약상 필수. 실 구현 필터 기준: >= 0.5
  modelResults: ModelResult[];
}

export interface AnalysisResult {
  scanId: string;
  success: boolean;
  errorMessage?: string;
  totalFiles: number;
  totalLines: number;
  vulnerabilities: VulnerabilityItem[]; // consensusScore >= 0.5 결과만 포함
}
```

> **Consensus 판정 기준:**
> - `consensusScore = 1.0` → 전 모델 합의 → 즉시 리포트
> - `0.5 <= consensusScore < 1.0` → 부분 합의 → UI에 '검토 권장' 배지 + modelResults 근거 표시
> - `consensusScore < 0.5` → 합의 미달 → 결과에서 제외 (구현체 책임)

### 7.2 Mock 구현체

```typescript
// client/analysis/mock-analysis-api.client.ts

@Injectable()
export class MockAnalysisApiClient implements IAnalysisApiClient {

  async analyze(request: AnalysisRequest, _options?: { signal?: AbortSignal }): Promise<AnalysisResult> {
    // 실제 API 지연 시뮬레이션 (3~8초)
    await new Promise(resolve =>
      setTimeout(resolve, 3000 + Math.random() * 5000)
    );

    return {
      scanId: request.scanId,
      success: true,
      totalFiles: 24,
      totalLines: 3842,
      vulnerabilities: [
        {
          title: 'SQL Injection — UserRepository.findByName()',
          description: '사용자 입력값이 SQL 쿼리에 직접 삽입되어 SQL Injection 공격에 취약합니다.',
          severity: 'CRITICAL',
          filePath: 'src/main/java/com/example/UserRepository.java',
          lineStart: 42,
          lineEnd: 45,
          codeSnippet: `String query = "SELECT * FROM users WHERE name = '" + name + "'";\nreturn jdbcTemplate.query(query, ...);`,
          fixSuggestion: `- String query = "SELECT * FROM users WHERE name = '" + name + "'";\n+ String query = "SELECT * FROM users WHERE name = ?";\n+ return jdbcTemplate.query(query, new Object[]{name}, ...);`,
          fixExplanation: '파라미터화된 쿼리(Prepared Statement)를 사용하면 사용자 입력이 SQL 코드로 해석되지 않아 SQL Injection을 방지할 수 있습니다.',
          cweId: 'CWE-89',
          owaspCategory: 'A03:2021-Injection',
          referenceLinks: [
            { title: 'CWE-89: SQL Injection', url: 'https://cwe.mitre.org/data/definitions/89.html' },
            { title: 'OWASP SQL Injection Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html' },
          ],
          consensusScore: 1.0,
          modelResults: [
            { model: 'claude-3-5-sonnet', detected: true, severity: 'CRITICAL', reasoning: 'name 파라미터가 PreparedStatement 없이 문자열 연산으로 쿼리에 삽입됨' },
            { model: 'gemini-2.0-flash', detected: true, severity: 'CRITICAL', reasoning: 'JDBC 쿼리에서 사용자 입력 직접 삽입 패턴 감지 (CWE-89)' },
          ],
        },
        {
          title: 'Hardcoded Secret — JwtConfig.java',
          description: 'JWT 서명 키가 소스코드에 하드코딩되어 있어 노출 위험이 있습니다.',
          severity: 'HIGH',
          filePath: 'src/main/java/com/example/config/JwtConfig.java',
          lineStart: 15,
          codeSnippet: `private static final String SECRET = "mysecretkey123";`,
          fixSuggestion: `- private static final String SECRET = "mysecretkey123";\n+ private final String secret = System.getenv("JWT_SECRET");`,
          fixExplanation: '비밀 키는 환경 변수 또는 Secrets Manager를 통해 주입받아야 합니다.',
          cweId: 'CWE-798',
          owaspCategory: 'A02:2021-Cryptographic Failures',
          referenceLinks: [
            { title: 'CWE-798: Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html' },
          ],
          consensusScore: 0.5,   // 부분 합의 — UI에 '검토 권장' 표시
          modelResults: [
            { model: 'claude-3-5-sonnet', detected: true, severity: 'HIGH', reasoning: '하드코딩된 JWT secret 상수 감지 (CWE-798)' },
            { model: 'gemini-2.0-flash', detected: false, severity: 'INFO', reasoning: '테스트 환경 코드일 가능성 있음. 추가 컨텍스트 필요.' },
          ],
        },
      ],
    };
  }
}
```

### 7.3 AnalysisApiModule 등록

```typescript
// client/analysis/analysis-api.module.ts

@Module({
  providers: [
    {
      provide: 'IAnalysisApiClient',
      useClass: MockAnalysisApiClient,
      // ⚠️ InternalAnalysisApiClient 전환 방법:
      // USE_INTERNAL_AI=true 환경변수 설정 후 아래 factory 패턴으로 교체:
      //
      // useFactory: (httpService: HttpService, config: ConfigService) =>
      //   config.get('USE_INTERNAL_AI') === 'true'
      //     ? new InternalAnalysisApiClient(httpService, config)
      //     : new MockAnalysisApiClient(),
      // inject: [HttpService, ConfigService],
      //
      // InternalAnalysisApiClient 사용 시 HttpModule(@nestjs/axios)을 반드시 imports에 등록할 것.
    },
  ],
  exports: ['IAnalysisApiClient'],
})
export class AnalysisApiModule {}
```

### 7.4 InternalAnalysisApiClient (NestJS → apps/ai 호출, 선택 통합)

```typescript
// client/analysis/internal-analysis-api.client.ts

@Injectable()
export class InternalAnalysisApiClient implements IAnalysisApiClient {

  constructor(
    private readonly httpService: HttpService,  // @nestjs/axios
    private readonly config: ConfigService,
  ) {}

  async analyze(request: AnalysisRequest, options?: { signal?: AbortSignal }): Promise<AnalysisResult> {
    const aiServerUrl = this.config.get('AI_SERVER_URL');  // http://localhost:8000
    const { signal } = options ?? {};

    try {
      const response = await firstValueFrom(
        this.httpService.post<AnalysisResult>(
          `${aiServerUrl}/analyze`,
          request,
          {
            timeout: 270_000,   // 4분 30초 (앱 레벨 스캔 타임아웃 5분보다 30초 짧게 설정)
            signal,
            headers: {
              'Content-Type': 'application/json',
              'X-Internal-Secret': this.config.get('INTERNAL_API_SECRET'),
            },
          },
        ),
      );
      return response.data;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        scanId: request.scanId,
        success: false,
        errorMessage: message,
        totalFiles: 0,
        totalLines: 0,
        vulnerabilities: [],
      };
    }
  }
}
```

### 7.5 apps/ai — `/analyze` 엔드포인트 명세 (선택 통합)

> Phase 1 완료의 필수 조건이 아니다. AI 팀이 구현해야 할 FastAPI 엔드포인트 명세이다.

```python
# apps/ai/schemas/request.py
from pydantic import BaseModel
from typing import Optional

class AnalyzeRequest(BaseModel):
    scanId: str
    cloneUrl: str
    branch: str
    commitSha: Optional[str] = None
    language: str           # 현재 "java" 고정
    accessToken: str        # private 레포 접근용 Git 토큰

# apps/ai/schemas/response.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ModelResult(BaseModel):
    model: str
    detected: bool
    severity: SeverityEnum
    reasoning: str          # 한국어 판단 근거

class VulnerabilityItem(BaseModel):
    title: str
    description: str
    severity: SeverityEnum
    filePath: str
    lineStart: int
    lineEnd: Optional[int] = None
    codeSnippet: Optional[str] = None
    fixSuggestion: Optional[str] = None
    fixExplanation: Optional[str] = None
    cweId: Optional[str] = None
    cveId: Optional[str] = None
    owaspCategory: Optional[str] = None
    referenceLinks: Optional[List[dict]] = None  # [{ "title": str, "url": str }]
    consensusScore: float                         # 필수 (>= 0.5만 반환)
    modelResults: List[ModelResult]

class AnalyzeResponse(BaseModel):
    scanId: str
    success: bool
    errorMessage: Optional[str] = None
    totalFiles: int
    totalLines: int
    vulnerabilities: List[VulnerabilityItem]
```

```python
# apps/ai/routers/analyze.py
from fastapi import APIRouter
from schemas.request import AnalyzeRequest
from schemas.response import AnalyzeResponse
from models.registry import ModelRegistry
from consensus.engine import ConsensusEngine
import asyncio

router = APIRouter()

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    models = ModelRegistry.get_all()

    # 모든 모델 병렬 실행 — 한 모델 실패 시 나머지 결과로 계속 진행
    results = await asyncio.gather(
        *[m.detect(request) for m in models],
        return_exceptions=True
    )

    valid_results = [r for r in results if not isinstance(r, Exception)]
    vulnerabilities = ConsensusEngine.aggregate(valid_results)

    return AnalyzeResponse(
        scanId=request.scanId,
        success=True,
        totalFiles=0,   # 구현체에서 실제 값으로 채울 것
        totalLines=0,
        vulnerabilities=vulnerabilities,
    )
```

```python
# apps/ai/consensus/engine.py
class ConsensusEngine:
    CONSENSUS_THRESHOLD = 0.5

    @staticmethod
    def aggregate(model_outputs: list) -> list:
        """
        - 동일 취약점 판정 기준: filePath + lineStart 일치
        - consensusScore = 탐지한 모델 수 / 전체 모델 수
        - consensusScore < CONSENSUS_THRESHOLD 항목은 제외
        - detected=False 모델 결과는 severity='INFO'를 기본값으로 사용
        """
        ...
```

---

## 8. 핵심 모듈 설계

### 8.1 ScanService + ScanProcessor 흐름

> **BullMQ 설정:**
> - 동시성: `concurrency: 3`
> - 앱 레벨 스캔 타임아웃: **5분** — `ScanProcessor` 내부에서 `AbortController`/`Promise.race` 등으로 외부 호출 시간을 제한하고, 타임아웃 시 Scan을 `FAILED`로 전환한다.
> - 재시도: 없음 (`attempts: 1`) — 실패 시 사용자가 수동으로 재스캔
> - Worker 레벨 설정에서 `lockDuration: 600000` (10분)을 권장한다.
>
> **동시 스캔 중복 방지:** MVP 필수 규칙이다. `ConnectedRepo` 단위 PostgreSQL advisory lock(또는 동등한 분산 락)을 잡은 뒤 활성 스캔 존재 여부를 확인하고 생성해야 한다. BullMQ `jobId`만으로는 DB 레코드 중복 생성을 막지 못한다.

```typescript
// scan/scan.service.ts
@Injectable()
export class ScanService {

  constructor(
    private prisma: PrismaService,
    @InjectQueue('scan-jobs') private scanQueue: Queue,
    private languageHandlerRegistry: LanguageHandlerRegistry,
  ) {}

  async requestScan(userId: string, repoId: string, branch: string) {
    const repo = await this.prisma.connectedRepo.findFirst({
      where: { id: repoId, userId },
    });
    if (!repo) throw new NotFoundException('연동된 레포를 찾을 수 없습니다.');

    // Phase 1: language는 항상 "java" 기본값 사용 (DB 스키마 @default("java")).
    // 향후 다중 언어 지원 시 요청 body에 language 필드를 추가하고 아래 검증 로직을 활용한다.
    const language = 'java';
    // 지원 여부 검증 — 미지원 언어이면 Error throw. Phase 1에서는 'java'만 등록되어 있으므로 항상 통과
    this.languageHandlerRegistry.get(language);

    // 경쟁 상태 방지: repoId 단위 advisory lock을 먼저 획득한 뒤 중복 체크 + 생성을 처리
    const scan = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${repoId}))`;

      const active = await tx.scan.findFirst({
        where: { connectedRepoId: repoId, status: { in: ['PENDING', 'RUNNING'] } }
      });
      if (active) throw new ConflictException('이미 대기 중이거나 실행 중인 스캔이 있습니다.');

      return tx.scan.create({
        data: { connectedRepoId: repoId, branch, status: 'PENDING' }
      });
    });

    await this.scanQueue.add('execute-scan', { scanId: scan.id }, {
      jobId: scan.id,
      attempts: 1,
    });

    return {
      scanId: scan.id,
      status: 'PENDING' as const,
      message: '스캔이 대기열에 등록되었습니다.',
    };
  }

  // [Phase 2] PR 자동 트리거 스캔 — Webhook에서 호출
  // 동일 레포를 여러 사용자가 연동한 경우 각각 스캔 큐잉
  async requestScanFromPR(params: {
    provider: 'github' | 'gitlab';
    providerRepoId: string;
    branch: string;
    prNumber: number;
  }) {
    const repos = await this.prisma.connectedRepo.findMany({
      where: { provider: params.provider.toUpperCase() as RepoProvider, providerRepoId: params.providerRepoId }
    });
    if (repos.length === 0) return;

    for (const repo of repos) {
      const scan = await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${repo.id}))`;

        const active = await tx.scan.findFirst({
          where: { connectedRepoId: repo.id, status: { in: ['PENDING', 'RUNNING'] } }
        });
        if (active) return null;

        return tx.scan.create({
          data: { connectedRepoId: repo.id, branch: params.branch, status: 'PENDING' }
        });
      });
      if (!scan) continue;

      await this.scanQueue.add('execute-scan', { scanId: scan.id }, {
        jobId: scan.id,
        attempts: 1,
      });
    }
  }
}

// scan/scan.processor.ts
@Processor('scan-jobs', { concurrency: 3, lockDuration: 600_000 })  // lockDuration: 10분 (ms)
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(
    private prisma: PrismaService,
    private gitClientRegistry: GitClientRegistry,
    @Inject('IAnalysisApiClient') private analysisClient: IAnalysisApiClient,
    private tokenCrypto: TokenCryptoUtil,  // ← AuthService 대신 직접 주입 (모듈 결합도 최소화)
  ) {
    super();
  }

  async process(job: Job<{ scanId: string }>) {
    const { scanId } = job.data;

    await this.prisma.scan.update({
      where: { id: scanId },
      data: { status: 'RUNNING', startedAt: new Date() }
    });

    try {
      const scan = await this.prisma.scan.findUnique({
        where: { id: scanId },
        include: { connectedRepo: { include: { user: { include: { oauthTokens: true } } } } }
      });

      if (!scan) throw new Error(`Scan not found: ${scanId}`);

      // ⚠️ OAuthToken.accessToken은 AES-256-GCM으로 암호화 저장됨.
      // 반드시 AuthService.decryptToken()으로 복호화 후 Analysis API에 전달해야 한다.
      const oauthToken = scan.connectedRepo.user.oauthTokens.find(
        t => t.provider === scan.connectedRepo.provider
      );
      if (!oauthToken) throw new Error(`OAuth token not found for provider: ${scan.connectedRepo.provider}`);

      const decryptedAccessToken = this.tokenCrypto.decrypt(oauthToken.accessToken);

      const gitClient = this.gitClientRegistry.get(scan.connectedRepo.provider.toLowerCase());
      const commitSha = await gitClient.getLatestCommitSha(
        scan.connectedRepo.fullName,
        scan.branch,
        decryptedAccessToken,
      );

      // 앱 레벨 스캔 타임아웃: 5분
      // 중요: Promise.race만으로는 HTTP 요청이 실제 중단되지 않을 수 있으므로,
      // AbortController.signal을 analysisClient → Axios/HTTP 레이어까지 전달해야 한다.
      const SCAN_TIMEOUT_MS = 5 * 60 * 1000;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
      let result: AnalysisResult;
      try {
        result = await Promise.race([
          this.analysisClient.analyze(
            {
              scanId,
              cloneUrl: scan.connectedRepo.cloneUrl,
              branch: scan.branch,
              commitSha,
              language: scan.language,
              accessToken: decryptedAccessToken,
            },
            { signal: controller.signal },
          ),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('분석 시간 초과 (5분)')), SCAN_TIMEOUT_MS)
          ),
        ]);
      } finally {
        clearTimeout(timeout);  // 성공/실패 모두 timeout 정리 (리소스 누수 방지)
      }

      if (!result.success) {
        throw new Error(result.errorMessage ?? 'Analysis API 호출에 실패했습니다.');
      }

      // ⚠️ VulnerabilityItem의 referenceLinks(object[])와 modelResults(object[])는
      // Prisma Json 컬럼 저장 시 InputJsonValue 타입 불일치 오류가 발생할 수 있다.
      // 아래와 같이 명시적 캐스팅을 적용한다.
      await this.prisma.vulnerability.createMany({
        data: result.vulnerabilities.map(v => ({
          scanId,
          title: v.title,
          description: v.description,
          severity: v.severity,
          filePath: v.filePath,
          lineStart: v.lineStart,
          lineEnd: v.lineEnd ?? null,
          codeSnippet: v.codeSnippet ?? null,
          fixSuggestion: v.fixSuggestion ?? null,
          fixExplanation: v.fixExplanation ?? null,
          cweId: v.cweId ?? null,
          cveId: v.cveId ?? null,
          owaspCategory: v.owaspCategory ?? null,
          referenceLinks: (v.referenceLinks ?? null) as Prisma.InputJsonValue,
          consensusScore: v.consensusScore,
          modelResults: v.modelResults as Prisma.InputJsonValue,
        })),
      });

      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'DONE',
          commitSha,
          totalFiles: result.totalFiles,
          totalLines: result.totalLines,
          vulnCritical: result.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
          vulnHigh: result.vulnerabilities.filter(v => v.severity === 'HIGH').length,
          vulnMedium: result.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
          vulnLow: result.vulnerabilities.filter(v => v.severity === 'LOW').length,
          vulnInfo: result.vulnerabilities.filter(v => v.severity === 'INFO').length,
          completedAt: new Date(),
        }
      });

    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      const axiosStatus = (err as any)?.response?.status;
      const errorMessage = error.message?.includes('token') || axiosStatus === 401
        ? '인증 토큰이 만료되었습니다. 다시 로그인하여 연동을 갱신해주세요.'
        : error.message;

      try {
        await this.prisma.scan.update({
          where: { id: scanId },
          data: { status: 'FAILED', errorMessage, completedAt: new Date() }
        });
      } catch (dbError) {
        this.logger.error(
          `CRITICAL: Failed to update scan status to FAILED. Scan ${scanId} may be stuck in RUNNING state.`,
          dbError instanceof Error ? dbError.stack : String(dbError),
          'ScanProcessor',
        );
        // RUNNING 상태 복구는 StuckScanRecoveryTask 스케줄러가 담당한다.
      }
    }
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job<{ scanId: string }>, error: Error) {
    this.logger.error(
      `Scan job failed: ${job.data.scanId}`,
      error.stack,
      'ScanProcessor',
    );
  }
}
```

> **BullMQ Dead Letter Queue:**
> - `attempts: 1`이므로 실패한 Job은 BullMQ의 `failed` 상태로 남는다.
> - 실패 Job 추적을 위해 `ScanProcessor`에 `@OnWorkerEvent('failed')` 데코레이터로 실패 이벤트 핸들러를 등록한다 (위 코드 참조).
> - 핸들러에서 `Logger.error`로 scanId, 에러 메시지, 스택 트레이스를 기록한다.
> - Phase 2에서 별도 Dead Letter Queue를 도입하여 실패 Job을 이동시키고, 관리자 대시보드에서 재처리하는 기능을 구현한다.

#### RUNNING 상태 타임아웃 복구 스케줄러 (`StuckScanRecoveryTask`)

> DB 업데이트 자체가 실패하여 스캔이 RUNNING 상태에 고착될 경우를 대비한 복구 스케줄러이다.
> `@nestjs/schedule` 모듈 사용 (NestJS Cron).

```typescript
// scan/stuck-scan-recovery.task.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class StuckScanRecoveryTask {
  private readonly logger = new Logger(StuckScanRecoveryTask.name);
  private readonly STUCK_THRESHOLD_MINUTES = 10;

  constructor(private prisma: PrismaService) {}

  // 5분마다 실행 — PENDING/RUNNING 상태로 10분 이상 멈춘 스캔을 FAILED로 전환
  @Cron('*/5 * * * *')
  async handleStuckScans() {
    const threshold = new Date(Date.now() - this.STUCK_THRESHOLD_MINUTES * 60 * 1000);
    const stuckScans = await this.prisma.scan.updateMany({
      where: {
        status: { in: ['PENDING', 'RUNNING'] },
        updatedAt: { lt: threshold },
      },
      data: {
        status: 'FAILED',
        errorMessage: '스캔 처리 시간이 초과되어 자동으로 실패 처리되었습니다.',
        completedAt: new Date(),
      },
    });
    if (stuckScans.count > 0) {
      this.logger.warn(`Recovered ${stuckScans.count} stuck scans`);
    }
  }
}
```

> `StuckScanRecoveryTask`를 `ScanModule`의 `providers` 배열에 추가하고, `AppModule`에서 `ScheduleModule.forRoot()`를 imports에 등록한다.

#### scan.module.ts — ScanModule 전체 구성

```typescript
// scan/scan.module.ts
import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ScanController } from './scan.controller';
import { ScanService } from './scan.service';
import { ScanProcessor } from './scan.processor';
import { StuckScanRecoveryTask } from './stuck-scan-recovery.task';
import { PrismaModule } from '../prisma/prisma.module';
import { AnalysisApiModule } from '../client/analysis/analysis-api.module';
import { GitClientModule } from '../client/git/git-client.module';
import { AuthModule } from '../auth/auth.module';
import { LanguageModule } from '../language/language.module';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'scan-jobs',
      defaultJobOptions: { attempts: 1, removeOnComplete: true, removeOnFail: false },
    }),
    PrismaModule,
    AnalysisApiModule,
    GitClientModule,
    AuthModule,      // TokenCryptoUtil export 용도 (auth.module.ts에서 TokenCryptoUtil을 exports에 추가할 것)
    LanguageModule,  // LanguageHandlerRegistry — ScanService에서 언어 검증 시 필요
  ],
  controllers: [ScanController],
  providers: [ScanService, ScanProcessor, StuckScanRecoveryTask],
  exports: [ScanService],  // WebhookModule에서 ScanService.requestScanFromPR() 호출 시 필요
})
export class ScanModule {}
```

> **⚠️ `TokenCryptoUtil` export 설정:** `ScanProcessor`가 `TokenCryptoUtil`을 직접 주입받으므로, `auth.module.ts`의 `exports` 배열에 `TokenCryptoUtil`을 추가해야 한다. 또는 `TokenCryptoUtil`을 독립적인 `CryptoModule`로 분리하여 `ScanModule`에서 직접 import하는 방법도 가능하다 (결합도 최소화).

#### TokenCryptoUtil — AES-256-GCM 토큰 암/복호화

```typescript
// auth/utils/token-crypto.util.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '../../config/config.service';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

@Injectable()
export class TokenCryptoUtil {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;

  constructor(private readonly config: ConfigService) {
    // TOKEN_ENCRYPTION_KEY: hex 인코딩된 64자 문자열 (32바이트)
    const keyHex = this.config.get('TOKEN_ENCRYPTION_KEY');
    this.key = Buffer.from(keyHex, 'hex');
    if (this.key.length !== 32) {
      throw new Error(
        `Invalid TOKEN_ENCRYPTION_KEY: expected 32 bytes (64 hex characters), got ${this.key.length} bytes. ` +
        'Generate a valid key using: openssl rand -hex 32'
      );
    }
  }

  /**
   * 평문을 AES-256-GCM으로 암호화한다.
   * 반환 포맷: `${iv_hex}:${authTag_hex}:${encrypted_hex}`
   */
  encrypt(plainText: string): string {
    const iv = randomBytes(12); // 96-bit IV (NIST SP 800-38D AES-GCM 표준 권장)
    const cipher = createCipheriv(this.algorithm, this.key, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * `encrypt()`로 생성된 문자열을 복호화한다.
   */
  decrypt(encryptedText: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedText.split(':');
    if (!ivHex || !authTagHex || !encrypted) {
      throw new Error('Invalid encrypted token format. Expected format: {iv_hex}:{authTag_hex}:{encrypted_hex}');
    }
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
}
```

### 8.2 ILanguageHandler — 언어 확장 구조

```typescript
// language/language-handler.interface.ts
export interface ILanguageHandler {
  getLanguage(): string;
  getFileExtensions(): string[];
  preProcess?(request: AnalysisRequest): AnalysisRequest;
}

// language/handlers/java.language-handler.ts
@Injectable()
export class JavaLanguageHandler implements ILanguageHandler {
  getLanguage() { return 'java'; }
  getFileExtensions() { return ['.java']; }
}

// language/language-handler.registry.ts
@Injectable()
export class LanguageHandlerRegistry {
  private handlers = new Map<string, ILanguageHandler>();

  register(handler: ILanguageHandler) {
    this.handlers.set(handler.getLanguage(), handler);
  }

  get(language: string): ILanguageHandler {
    const handler = this.handlers.get(language);
    if (!handler) throw new Error(`Unsupported language: ${language}`);
    return handler;
  }
}
```

> 도메인 로직에 언어 문자열(`'java'`)을 산발적으로 직접 비교하지 않는다. 항상 Registry를 통해 처리한다.

모듈 초기화 시 핸들러 등록 예시:

```typescript
// language/language.module.ts
@Module({
  providers: [
    LanguageHandlerRegistry,
    JavaLanguageHandler,
  ],
  exports: [LanguageHandlerRegistry],
})
export class LanguageModule implements OnModuleInit {
  constructor(
    private registry: LanguageHandlerRegistry,
    private java: JavaLanguageHandler,
  ) {}
  onModuleInit() {
    this.registry.register(this.java);
  }
}
```

### 8.3 Git Provider 클라이언트 구조

```typescript
// client/git/git-provider-client.interface.ts
export interface IGitProviderClient {
  getRepositories(accessToken: string, page: number, size: number): Promise<RepoListResult>;
  getLatestCommitSha(fullName: string, branch: string, accessToken: string): Promise<string>;
}

export interface RepoListResult {
  items: {
    providerRepoId: string;
    fullName: string;
    cloneUrl: string;
    defaultBranch: string;
    isPrivate: boolean;
  }[];
  totalCount: number;
}
```

구현 원칙:
- `GithubClient`, `GitlabClient` 각각 구현, `GitClientRegistry`로 provider 문자열 기반 조회
- 외부 API pagination과 내부 `PageResponse` pagination을 명시적으로 매핑한다
- 401 → 토큰 만료/무효로 처리, 404 → 레포 접근 불가 또는 삭제로 처리

모듈 초기화 시 클라이언트 등록 예시:

```typescript
// client/git/git-client.module.ts
@Module({
  providers: [
    GitClientRegistry,
    GithubClient,
    GitlabClient,
  ],
  exports: [GitClientRegistry],
})
export class GitClientModule implements OnModuleInit {
  constructor(
    private registry: GitClientRegistry,
    private github: GithubClient,
    private gitlab: GitlabClient,
  ) {}
  onModuleInit() {
    this.registry.register('github', this.github);
    this.registry.register('gitlab', this.gitlab);
  }
}
```

### 8.4 에러 시나리오 및 복구 전략

| 시나리오 | 발생 지점 | 동작 | 사용자 알림 |
|----------|----------|------|------------|
| Analysis API 타임아웃 (5분 초과) | ScanProcessor | Scan → FAILED, `errorMessage: '분석 시간 초과'` | 폴링 응답에서 확인 |
| Analysis API 부분 성공 (일부 파일만 분석) | IAnalysisApiClient | `success: true` + 실제 처리된 파일 수를 `totalFiles`에 반영 | 대시보드에서 totalFiles 확인 |
| OAuth 토큰 만료 (401) | ScanProcessor → GitClient | Scan → FAILED, `errorMessage: '인증 토큰이 만료되었습니다. 다시 로그인하여 연동을 갱신해주세요.'` | 폴링 응답 + 프론트 토스트 |
| DB 트랜잭션 실패 | ScanService.requestScan | 트랜잭션 롤백, HTTP 500 반환 | 프론트 글로벌 에러 핸들러 |
| BullMQ Job과 DB 상태 불일치 | ScanProcessor catch 블록 | catch 블록에서 반드시 Scan 상태를 FAILED로 업데이트. 만약 이 업데이트마저 실패하면 NestJS Logger.error로 기록하고, 별도 RUNNING 상태 타임아웃 스케줄러(StuckScanRecoveryTask)로 복구한다. | 관리자 로그 확인 |
| Redis 연결 실패 | BullMQ Worker 시작 | Worker 재연결 시도 (BullMQ 기본 동작). Health Check에서 `redis: 'down'` 반환 | `/api/health` 모니터링 |
| Git Provider API Rate Limit (403/429) | GitClient | 에러를 상위로 전파, Scan → FAILED, `errorMessage`에 Rate Limit 정보 포함 | 폴링 응답 |
| 동시 스캔 중복 요청 경쟁 상태 | ScanService | Prisma 트랜잭션 격리로 방지. 트랜잭션 내부에서 중복 체크 + 생성을 원자적으로 수행 | 409 ConflictException |

#### GlobalExceptionFilter — 전역 예외 처리 필터

```typescript
// common/filters/global-exception.filter.ts
import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { Response } from 'express';
import type { ErrorResponse } from '@aegisai/shared';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = '서버 내부 오류가 발생했습니다.';
    let errorCode = 'INTERNAL_ERROR';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();
      message = typeof res === 'string' ? res : (res as any).message ?? message;
      errorCode = (res as any).errorCode ?? this.statusToErrorCode(status);
    }

    if (status >= 500) {
      this.logger.error(
        `[${errorCode}] ${message}`,
        exception instanceof Error ? exception.stack : undefined,
      );
    }

    const errorResponse: ErrorResponse = {
      success: false,
      data: null,
      message,
      errorCode,
      timestamp: new Date().toISOString(),
    };

    response.status(status).json(errorResponse);
  }

  private statusToErrorCode(status: number): string {
    const map: Record<number, string> = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED',
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      409: 'CONFLICT',
      429: 'TOO_MANY_REQUESTS',
    };
    return map[status] ?? 'INTERNAL_ERROR';
  }
}
```

#### ResponseTransformInterceptor — 응답 자동 래핑 인터셉터

```typescript
// common/interceptors/response-transform.interceptor.ts
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable, map } from 'rxjs';
import { Reflector } from '@nestjs/core';
import type { SuccessResponse } from '@aegisai/shared';

@Injectable()
export class ResponseTransformInterceptor<T> implements NestInterceptor<T, SuccessResponse<T>> {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<SuccessResponse<T>> {
    return next.handle().pipe(
      map((data) => {
        // @HttpCode() 데코레이터로 설정한 상태 코드를 보존한다 (예: 202)
        // NestJS는 @HttpCode()가 있으면 이미 response.statusCode를 설정한 상태이므로 별도 처리 불필요

        // Health Check 등 래핑 제외가 필요한 경우 커스텀 데코레이터로 처리:
        // @SkipTransform() → Reflector로 확인 후 raw data 반환
        const skipTransform = this.reflector.get<boolean>('skipTransform', context.getHandler());
        if (skipTransform) return data as any;

        return {
          success: true as const,
          data,
          message: null,
          timestamp: new Date().toISOString(),
        };
      }),
    );
  }
}
```

#### ResourceOwnerGuard — 리소스 소유권 검증 가드

```typescript
// common/guards/resource-owner.guard.ts
import { Injectable, CanActivate, ExecutionContext, NotFoundException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * 리소스 소유권 검증 가드.
 *
 * @ResourceOwnerCheck('scan') → Scan → ConnectedRepo → User 경로 검증
 * @ResourceOwnerCheck('vulnerability') → Vulnerability → Scan → ConnectedRepo → User 경로 검증
 *
 * URL 파라미터에서 리소스 ID를 추출하여 소유권을 확인한다.
 * 파라미터 이름은 :scanId, :vulnId 등 리소스 타입에 따라 자동 매핑된다.
 */
@Injectable()
export class ResourceOwnerGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const resourceType = this.reflector.get<string>('resourceType', context.getHandler());
    if (!resourceType) return true;

    const request = context.switchToHttp().getRequest();
    const userId = request.user?.id;
    if (!userId) return false; // SessionAuthGuard가 먼저 적용되어야 한다 (미인증 요청은 여기에 도달하지 않아야 함)

    switch (resourceType) {
      case 'scan':
        return this.verifyScanOwner(request.params.scanId, userId);
      case 'vulnerability':
        return this.verifyVulnerabilityOwner(request.params.vulnId, userId);
      default:
        return true;
    }
  }

  private async verifyScanOwner(scanId: string, userId: string): Promise<boolean> {
    const scan = await this.prisma.scan.findUnique({
      where: { id: scanId },
      include: { connectedRepo: { select: { userId: true } } },
    });
    if (!scan) throw new NotFoundException('스캔을 찾을 수 없습니다.');
    return scan.connectedRepo.userId === userId;
  }

  private async verifyVulnerabilityOwner(vulnId: string, userId: string): Promise<boolean> {
    const vuln = await this.prisma.vulnerability.findUnique({
      where: { id: vulnId },
      include: { scan: { include: { connectedRepo: { select: { userId: true } } } } },
    });
    if (!vuln) throw new NotFoundException('취약점을 찾을 수 없습니다.');
    return vuln.scan.connectedRepo.userId === userId;
  }
}

// common/decorators/resource-owner-check.decorator.ts
import { SetMetadata } from '@nestjs/common';
export const ResourceOwnerCheck = (resourceType: string) => SetMetadata('resourceType', resourceType);

// 사용 예시 (Controller):
// @Get(':scanId')
// @UseGuards(SessionAuthGuard, ResourceOwnerGuard)
// @ResourceOwnerCheck('scan')
// async getScan(@Param('scanId') scanId: string) { ... }
```

---

## 9. GitHub/GitLab 연동 플로우

### 9.1 OAuth App vs Webhook 역할 구분

- **GitHub OAuth App / GitLab OAuth Application**: 사용자 로그인 및 저장소 접근 권한 획득에 사용한다.
- **GitHub Webhook 또는 GitHub App Webhook**: PR 이벤트 자동 감지에 사용한다.
- 두 설정은 별개이며, OAuth 설정만으로 Webhook이 자동 구성되지 않는다.

### 9.2 환경 변수 설정

```bash
# GitHub OAuth App 설정 — https://github.com/settings/developers
# Callback URL: http://localhost:3000/api/auth/github/callback
GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx

# GitLab Application 설정 — https://gitlab.com/-/user_settings/applications
# Callback URL: http://localhost:3000/api/auth/gitlab/callback
# Scopes: read_user, read_api
# private 레포 코드 접근이 필요할 경우 read_repository scope 추가를 검토한다. read_api가 repository 접근을 포함하나 명시적 추가 권장.
GITLAB_CLIENT_ID=xxx
GITLAB_CLIENT_SECRET=xxx
```

### 9.3 Passport Strategy

> **OAuth `state` 파라미터 검증:** `passport-github2`와 `passport-gitlab2`에서 `state: true`를 명시적으로 활성화해야 OAuth2 `state`가 생성·검증된다. `state` 값은 세션에 저장되므로, 세션 설정이 OAuth 인증보다 먼저 초기화되어야 한다 (main.ts의 middleware 순서 참조).

```typescript
// auth/strategies/github.strategy.ts
@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(private authService: AuthService, config: ConfigService) {
    super({
      clientID: config.get('GITHUB_CLIENT_ID'),
      clientSecret: config.get('GITHUB_CLIENT_SECRET'),
      callbackURL: `${config.get('APP_URL')}/api/auth/github/callback`,
      state: true,
      scope: ['read:user', 'user:email', 'repo'],
    });
  }

  async validate(accessToken: string, _refreshToken: string, profile: any) {
    return this.authService.findOrCreateUser('github', profile, accessToken);
  }
}

// auth/strategies/gitlab.strategy.ts
// passport-gitlab2 패키지의 Strategy를 import한다
@Injectable()
export class GitlabStrategy extends PassportStrategy(Strategy, 'gitlab') {
  constructor(private authService: AuthService, config: ConfigService) {
    super({
      clientID: config.get('GITLAB_CLIENT_ID'),
      clientSecret: config.get('GITLAB_CLIENT_SECRET'),
      callbackURL: `${config.get('APP_URL')}/api/auth/gitlab/callback`,
      state: true,
      scope: ['read_user', 'read_api'],
    });
  }

  async validate(accessToken: string, _refreshToken: string, profile: any) {
    return this.authService.findOrCreateUser('gitlab', profile, accessToken);
  }
}
```

> **⚠️ Passport 세션 사용 시 serializer/deserializer 구현 필수:** `auth.serializer.ts`에 `PassportSerializer`를 상속하여 `serializeUser`, `deserializeUser`를 구현해야 한다. 누락 시 로그인 후 세션이 유지되지 않는다.

```typescript
// auth/auth.serializer.ts
import { Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthSerializer extends PassportSerializer {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  serializeUser(user: { id: string }, done: (err: Error | null, id?: string) => void) {
    done(null, user.id);
  }

  async deserializeUser(userId: string, done: (err: Error | null, user?: any) => void) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        include: { oauthTokens: { select: { provider: true } } },
      });
      if (!user) {
        return done(null, null);
      }
      done(null, {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        connectedProviders: user.oauthTokens.map(t => t.provider.toLowerCase()),
      });
    } catch (err) {
      done(err as Error);
    }
  }
}
```

### 9.4 GitHub API 호출 헤더

```typescript
headers: {
  Authorization: `Bearer ${accessToken}`,
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
}
```

### 9.5 GitLab API 호출 헤더

```typescript
// GitLab API 헤더
headers: {
  'Authorization': `Bearer ${accessToken}`,
  'Content-Type': 'application/json',
}
```

### 9.6 GitHub / GitLab OAuth 프로필 객체 구조

`AuthService.findOrCreateUser()`에서 provider별로 다른 profile 필드 구조를 처리한다.

```typescript
// GitHub profile 구조
// profile.id            → providerUserId (number → string 변환)
// profile.emails[0]?.value → email
// profile.displayName ?? profile.username → name
// profile.photos[0]?.value → avatarUrl

// GitLab profile 구조
// profile.id            → providerUserId (number → string 변환)
// profile.emails[0]?.value → email
// profile.displayName   → name
// profile.avatarUrl     → avatarUrl
```

### 9.7 GitHub Webhook — PR 자동 트리거 [Phase 2]

> **`rawBody` 사전 설정 필요:** `main.ts`에서 아래 설정을 추가해야 한다.
>
> ```typescript
> const app = await NestFactory.create<NestExpressApplication>(AppModule, {
>   rawBody: true,
> });
> ```
>
> `@RawBody()` 커스텀 데코레이터를 `common/decorators/raw-body.decorator.ts`에 작성:
> ```typescript
> export const RawBody = createParamDecorator(
>   (_data: unknown, ctx: ExecutionContext): Buffer => {
>     const req = ctx.switchToHttp().getRequest();
>     return req.rawBody;
>   },
> );
> ```

```typescript
// webhook/webhook.controller.ts
@Post('github')
@HttpCode(200)
async handleGithubWebhook(
  @Headers('x-hub-signature-256') signature: string,
  @Headers('x-github-event') event: string,
  @Body() payload: any,
  @RawBody() rawBody: Buffer,  // 서명 검증에는 raw body 사용
) {
  this.verifySignature(signature, rawBody);  // HMAC-SHA256 검증

  if (event === 'pull_request' && ['opened', 'synchronize'].includes(payload.action)) {
    const { repository, pull_request } = payload;
    await this.scanService.requestScanFromPR({
      provider: 'github',
      providerRepoId: String(repository.id),
      branch: pull_request.head.ref,
      prNumber: pull_request.number,
    });
  }
}
```

> **설정:** Webhook URL: `https://{APP_URL}/api/webhook/github` (global prefix `/api` 포함 필수), Content type: `application/json`, Secret: `GITHUB_APP_WEBHOOK_SECRET`

### 9.8 GitHub Suggested Changes API [Phase 2]

> **주의:** 단일 라인 코멘트에 `start_line`을 포함하면 `422 Unprocessable Entity` 오류가 발생한다.

```typescript
// client/git/github.client.ts
async createSuggestedChange(params: {
  repoFullName: string;
  prNumber: number;
  filePath: string;
  lineStart: number;
  lineEnd: number | null;
  fixSuggestion: string;  // unified diff → suggestion 블록으로 변환
  accessToken: string;
}): Promise<{ commentId: string; htmlUrl: string }> {
  const body = this.diffToSuggestion(params.fixSuggestion);

  const comment: any = {
    path: params.filePath,
    line: params.lineEnd ?? params.lineStart,
    body,
  };

  // 다중 라인일 때만 start_line 포함 (단일 라인 시 422 방지)
  if (params.lineEnd && params.lineEnd > params.lineStart) {
    comment.start_line = params.lineStart;
  }

  const response = await this.axios.post(
    `https://api.github.com/repos/${params.repoFullName}/pulls/${params.prNumber}/reviews`,
    { event: 'COMMENT', comments: [comment] },
    { headers: this.getHeaders(params.accessToken) },
  );
  return { commentId: String(response.data.id), htmlUrl: response.data.html_url };
}
```

### 9.9 GitLab Webhook — MR 자동 트리거 [Phase 2]

```typescript
// Phase 2: GitLab Webhook — Merge Request 자동 트리거
// Webhook URL: https://{APP_URL}/api/webhook/gitlab
// Secret Token: GITLAB_WEBHOOK_SECRET (X-Gitlab-Token 헤더로 검증)
// 이벤트: Merge Request Events (open, update)
```

> GitLab Webhook 설정:
> - Project → Settings → Webhooks에서 URL 등록
> - Secret Token: `GITLAB_WEBHOOK_SECRET` 환경변수 값 입력
> - Trigger: Merge request events 체크
> - GitLab은 `X-Gitlab-Token` 헤더로 secret을 평문 비교하므로 GitHub HMAC 방식과 다름에 주의한다.

---

## 10. 개발 환경 설정

### 10.1 사전 요구사항

```bash
Node.js 20 LTS
pnpm 9.x          # npm install -g pnpm
Docker Desktop
```

> 패키지 매니저 고정: 루트 `package.json`에 `"packageManager": "pnpm@9.15.4"` 명시, `.npmrc`에 `engine-strict=true` 설정.

### 10.2 docker-compose.yml

```yaml
# Docker Compose V2 기준 — version 키는 더 이상 필수가 아니므로 생략
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: aegisai       # ⚠️ 소문자 사용 — 대소문자 혼용 시 따옴표 이슈 발생
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

  ai-server:                     # 선택 통합
    build:
      context: ./apps/ai
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - AI_SERVER_PORT=8000
      - MODEL_A_ID=${MODEL_A_ID}
      - MODEL_B_ID=${MODEL_B_ID}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./apps/ai:/app
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --reload

volumes:
  postgres_data:
```

### 10.3 루트 package.json

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
  },
  "devDependencies": {
    "concurrently": "^8.x"
  }
}
```

> **packages/shared 개발 모드 참고:** packages/shared는 TypeScript path alias 또는 tsconfig references로 소스를 직접 참조하므로 별도 빌드 없이 개발 모드에서 변경이 실시간 반영된다.

```yaml
# pnpm-workspace.yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

### 10.3-1 config.module.ts — 환경변수 유효성 검사 스키마

```typescript
// config/config.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { ConfigService } from './config.service';

@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      validationSchema: Joi.object({
        DATABASE_URL: Joi.string().uri().required(),
        REDIS_URL: Joi.string().uri().required(),
        SESSION_SECRET: Joi.string().min(16).required(),
        GITHUB_CLIENT_ID: Joi.string().required(),
        GITHUB_CLIENT_SECRET: Joi.string().required(),
        GITLAB_CLIENT_ID: Joi.string().required(),
        GITLAB_CLIENT_SECRET: Joi.string().required(),
        APP_URL: Joi.string().uri().required(),
        FRONTEND_URL: Joi.string().uri().required(),
        TOKEN_ENCRYPTION_KEY: Joi.string().length(64).required(),  // hex 인코딩 32바이트 = 64자
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
        AI_SERVER_URL: Joi.string().uri().default('http://localhost:8000'),
        USE_INTERNAL_AI: Joi.string().valid('true', 'false').default('false'),
        INTERNAL_API_SECRET: Joi.string().optional().allow(''),
        GITHUB_APP_WEBHOOK_SECRET: Joi.string().optional().allow(''),
        GITLAB_WEBHOOK_SECRET: Joi.string().optional().allow(''),
      }),
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {}
```

> **참고:** `joi` 패키지를 `apps/api` 의존성에 추가해야 한다 (`pnpm --filter @aegisai/api add joi`). 앱 시작 시 환경변수가 스키마를 통과하지 못하면 NestJS가 즉시 오류를 발생시켜 잘못된 설정으로 서버가 기동되는 것을 방지한다.

#### config.service.ts — 타입 안전 환경변수 접근

```typescript
// config/config.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';

@Injectable()
export class ConfigService {
  constructor(private readonly nestConfig: NestConfigService) {}

  /**
   * 환경변수 값을 타입 안전하게 조회한다.
   * Joi 스키마에서 required로 정의된 변수는 undefined가 아님이 보장된다.
   */
  get(key: string): string {
    const value = this.nestConfig.get<string>(key);
    if (value === undefined) {
      throw new Error(`Missing environment variable: ${key}`);
    }
    return value;
  }

  getOptional(key: string): string | undefined {
    return this.nestConfig.get<string>(key);
  }

  isProduction(): boolean {
    return this.get('NODE_ENV') === 'production';
  }

  isDevelopment(): boolean {
    return this.get('NODE_ENV') === 'development';
  }
}
```

### 10.4 main.ts 핵심 설정

```typescript
// apps/api/src/main.ts
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from './config/config.service';  // 커스텀 ConfigService (타입 안전 get() 메서드 제공)
import * as session from 'express-session';
import * as passport from 'passport';
import RedisStore from 'connect-redis';
import { createClient } from 'redis';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    rawBody: true,  // Webhook 서명 검증용 (Phase 2)
  });

  const configService = app.get(ConfigService);

  // 리버스 프록시 뒤 배포 시 req.ip / secure cookie 판정 보정
  app.set('trust proxy', 1);

  // CORS 설정 — 프론트엔드(5173)와 API(3000) 포트가 다르므로 필수
  app.enableCors({
    origin: configService.get('FRONTEND_URL'),
    credentials: true,  // 세션 쿠키 전달 허용
  });

  // Global Validation Pipe
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // Redis 클라이언트 생성 (세션 스토어용)
  const redisClient = createClient({ url: configService.get('REDIS_URL') });
  await redisClient.connect();

  // 세션 설정
  app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: configService.get('SESSION_SECRET'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 86400000,       // 24시간
      httpOnly: true,
      secure: configService.get('NODE_ENV') === 'production',
      sameSite: 'lax',
    },
  }));

  // Passport 세션 설정 순서 엄수: session → initialize → session
  app.use(passport.initialize());
  app.use(passport.session());

  // Swagger 설정
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Aegisai API')
    .setDescription('Aegisai Platform API Documentation')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api-docs', app, document);

  app.setGlobalPrefix('api');
  await app.listen(3000);
}
bootstrap();
```

> Rate limiting은 `APP_GUARD`에 기본 `ThrottlerGuard`를 그대로 등록하지 말고, 인증 사용자는 `req.sessionID`, 미인증 사용자는 `req.ip`를 tracker로 사용하는 커스텀 가드(`SessionAwareThrottlerGuard`)로 교체한다. `POST /api/scans`에는 별도 named throttler를 명시적으로 연결한다.

### 10.5 실행 순서

```bash
# 1. 의존성 설치
pnpm install

# 2. 인프라 시작
docker compose up -d

# 3. 환경변수 설정
cp apps/api/.env.example apps/api/.env
# .env 파일을 열어 GitHub OAuth App 등 필수 값을 입력한다.

# 4. DB 마이그레이션
pnpm db:migrate

# 5. (선택) apps/ai/.env 작성
# AI_SERVER_PORT=8000
# MODEL_A_ID=ft:gpt-4o-mini:your-org:model-a:xxx
# MODEL_B_ID=ft:gpt-4o-mini:your-org:model-b:xxx
# OPENAI_API_KEY=xxx

# 6. 전체 실행 (API: 3000, Web: 5173)
pnpm dev
```

---

## 11. 개발 태스크 (Phase별)

> **에이전트 지침:** 태스크를 순서대로 완료하고, 완료 시 체크박스에 표시한다.

### Phase 1 — 기반 구조 (필수 구현)

```text
[ ] TASK-01: Monorepo 초기화
    - pnpm workspace 설정 (루트 package.json, pnpm-workspace.yaml, .npmrc)
    - apps/api: NestJS CLI로 프로젝트 생성
    - apps/web: Vite + React + TypeScript 생성
    - packages/shared: 공유 타입 패키지 초기화 (name: @aegisai/shared)
    - docker-compose.yml 작성
    - CORS 설정 (main.ts — FRONTEND_URL origin 허용, credentials: true)
    - 루트에서 pnpm dev 실행 시 api + web 동시 구동 확인

[ ] TASK-02: Prisma 설정 및 DB 마이그레이션
    - schema.prisma 작성 (섹션 5 기준 — RepoProvider enum 포함)
    - prisma migrate dev 실행
    - PrismaService (NestJS Injectable) 작성
    - PrismaModule을 AppModule에 등록

[ ] TASK-03: 공유 타입 패키지 구성
    - packages/shared/src/types/ 하위 타입 파일 작성
    - ApiResponse<T>, PageResponse<T>, ErrorResponse (common.ts)
    - ScanStatus, Severity, VulnStatus, UserFeedback enum
    - apps/api, apps/web에서 @aegisai/shared import 확인

[ ] TASK-04: OAuth2 인증 구현
    - passport, passport-github2, passport-gitlab2 설치
    - GithubStrategy, GitlabStrategy 작성
    - AuthService.findOrCreateUser() — users upsert + oauth_tokens 저장
      (providerUserId 포함, AES-256-GCM 암호화, token-crypto.util.ts)
    - ⚠️ auth.serializer.ts 작성 (PassportSerializer 상속 — serializeUser/deserializeUser 필수)
    - 세션 설정 (express-session + connect-redis, TTL 24시간, httpOnly, sameSite: lax)
    - Passport middleware 등록 순서 준수: session → initialize → session
    - OAuth 성공 시 FRONTEND_URL/dashboard로 리다이렉트
    - AuthController: GET /api/auth/me, POST /api/auth/logout
    - SessionAuthGuard, CurrentUser 데코레이터
    - 통합 테스트: OAuth 콜백 → 세션 발급 → /api/auth/me 응답

[ ] TASK-05: IAnalysisApiClient 인터페이스 + Mock 구현
    - analysis-api-client.interface.ts 작성 (섹션 7.1)
    - AnalysisRequest, AnalysisResult, VulnerabilityItem, ModelResult 타입 작성
    - MockAnalysisApiClient 구현 (섹션 7.2 — consensusScore, modelResults 포함)
    - AnalysisApiModule 등록 (섹션 7.3)
    - Mock 단위 테스트: analyze() 호출 → AnalysisResult 반환 확인

[ ] TASK-06: ILanguageHandler 플러그인 구조
    - ILanguageHandler 인터페이스 작성
    - JavaLanguageHandler 구현
    - LanguageHandlerRegistry 작성
    - 등록 및 조회 단위 테스트

[ ] TASK-07: IGitProviderClient 구현
    - IGitProviderClient 인터페이스 작성
    - GithubClient 구현 (레포 목록, 브랜치 커밋 SHA 조회)
    - GitlabClient 구현 (동일)
    - GitClientRegistry — provider 문자열로 클라이언트 조회
    - 외부 API pagination ↔ 내부 PageResponse 매핑
    - 에러 핸들링 (401 토큰 만료, 404 레포 없음)

[ ] TASK-08: BullMQ 스캔 큐 + ScanProcessor 구현
    - @nestjs/bullmq, bullmq 설치 및 BullModule 설정 (Redis 연결)
    - Job 설정: attempts 1, concurrency 3, lockDuration 10분
    - 앱 레벨 스캔 타임아웃 5분 구현 (AbortController 또는 동등한 취소 전파 포함)
    - ScanService.requestScan() — PENDING 저장 + Job 등록 (advisory lock 기반 PENDING/RUNNING 중복 방지)
    - ScanProcessor(WorkerHost) — 섹션 8.1 전체 흐름 구현
      (토큰 복호화, Git 커밋 SHA 조회, Analysis API 호출, DB 저장, 상태 전환)
    - Prisma Json 컬럼 저장 시 InputJsonValue 캐스팅 적용
    - 통합 테스트: requestScan() → Job 처리 → Scan DONE + Vulnerability 저장 확인
```

### Phase 2 — REST API 레이어

> **참고:** 여기서의 Phase 1/2/3는 개발 순서를 의미한다. PRD의 Phase 2 기능(PR 자동 트리거·Suggested Changes 등)은 `TASK-**-P2` 태그로 구분한다.

```text
[ ] TASK-09: Repo API
    - RepoService: 연동 레포 CRUD, available 레포 조회 (GitProviderClient 활용)
    - RepoController: 섹션 6.3 전체 엔드포인트
    - node-cache로 /repos/available 응답 캐싱 (TTL 5분)
    - 통합 테스트 (Supertest)

[ ] TASK-10: Scan API
    - ScanController: 섹션 6.4 전체 엔드포인트
    - 폴링용 GET /scans/:id 응답 최적화
    - 통합 테스트

[ ] TASK-11: Vulnerability API
    - VulnerabilityService: 필터/정렬/페이지네이션
    - VulnerabilityController: 섹션 6.5 전체 엔드포인트 (consensusScore, modelResults 포함)
    - 통합 테스트

[ ] TASK-12: Dashboard API
    - DashboardService: Prisma 집계 쿼리 (30일 trend 포함)
    - DashboardController: 섹션 6.6
    - 통합 테스트

[ ] TASK-13: 공통 처리
    - GlobalExceptionFilter — ErrorResponse 형식으로 에러 응답 표준화
    - ResponseTransformInterceptor — ApiResponse<T> 자동 래핑 (Controller는 raw data만 반환)
    - SkipTransform 데코레이터 구현 (health, 204 응답 예외 처리)
    - SessionAwareThrottlerGuard 구현 (세션 ID/IP 기준 tracker)
    - @nestjs/swagger 설정 및 /api-docs 확인
    - @nestjs/throttler Rate Limiting 설정 (섹션 6.8 기준)

[ ] TASK-14: Health Check + DB 시드
    - HealthModule 구현 및 AppModule 등록
    - HealthController: GET /api/health (DB·Redis 연결 상태 확인, 섹션 6.7 기준)
    - prisma/seed.ts: 개발용 시드 데이터 (User, ConnectedRepo, Scan, Vulnerability — consensusScore 포함)
    - package.json prisma.seed 설정

[ ] TASK-15-P2: GitHub Webhook — PR 자동 트리거 [Phase 2]
    - WebhookModule, WebhookController 구현 (섹션 9.7)
    - HMAC-SHA256 서명 검증 (rawBody 설정 필요)
    - pull_request opened/synchronize → ScanService.requestScanFromPR() 연동
    - 통합 테스트: Webhook payload 시뮬레이션 → BullMQ Job 등록 확인

[ ] TASK-16-P2: GitHub Suggested Changes [Phase 2]
    - GithubClient.createSuggestedChange() 구현 (섹션 9.8)
    - VulnerabilityController: POST /api/vulnerabilities/:vulnId/suggest-change
    - unified diff → suggestion 코드 블록 변환 유틸
    - 통합 테스트
```

### Phase 3 — Frontend

```text
[ ] TASK-17: 레이아웃 및 공통 설정
    - shadcn/ui init, Tailwind 설정
    - AppShell (사이드바 + 헤더) 레이아웃
    - Axios 인스턴스 (baseURL, withCredentials: true)
    - Axios 응답 인터셉터: 401 → /login 리다이렉트 (인증 에러 전담)
    - TanStack Query QueryClient + 글로벌 에러 핸들러 (일반 에러 토스트 전담)
    - React Router 라우팅 설정
    - React ErrorBoundary (예기치 않은 에러 폴백 UI)

[ ] TASK-18: 인증 플로우
    - LoginPage — GitHub/GitLab 로그인 버튼
    - useAuth 훅 — GET /api/auth/me
    - Zustand auth store
    - ProtectedRoute — React Router v6 wrapper component 패턴으로 구현
    - 로그아웃

[ ] TASK-19: 레포 연동 페이지
    - ReposPage — 연동 레포 목록
    - RepoSelector 모달 — 신규 연동 플로우 (available 레포 선택)
    - 연동 해제

[ ] TASK-20: 스캔 실행 및 상태
    - ScanPage — 레포/브랜치 선택 → 스캔 시작
    - 3초 폴링 (DONE/FAILED 시 자동 중단)
    - ScanStatusBadge 컴포넌트

[ ] TASK-21: 취약점 목록 및 상세
    - VulnerabilitiesPage — 필터 + 정렬 + 페이지네이션
    - VulnerabilityDetailPage — 코드 스니펫 + diff 뷰어
    - ConsensusScoreBadge — 1.0: '완전 합의', < 1.0: '검토 권장' 배지
    - ModelResultsPanel — consensusScore < 1.0 시 모델별 판단 근거 아코디언
    - Accept/Reject 피드백 버튼

[ ] TASK-22: 대시보드
    - StatCard (심각도별 카운트)
    - SeverityPieChart (Recharts)
    - TrendLineChart (30일 추이)
    - 최근 스캔 목록
```

### Phase 2 고급 기능 (PRD Phase 2)

```text
[ ] TASK-23-P2: 피드백 기반 앙상블 가중치 자동 학습
    - PATCH /feedback에서 수집된 ACCEPTED/REJECTED 데이터 집계
    - 모델별 정탐률 계산 → ConsensusEngine 가중치 동적 조정
    - 가중치 저장: DB 또는 별도 설정 테이블
    - 관리자용 GET /api/admin/consensus-weights 엔드포인트
```

---

## 12. 코딩 컨벤션

### Backend (NestJS/TypeScript)

```typescript
// 1. 모든 외부 의존성은 인터페이스로 추상화 (I 접두사)
// 2. DTO는 class-validator 데코레이터 사용
// 3. 비즈니스 로직은 Service에만, Controller는 요청/응답 변환만
// 4. Prisma 쿼리는 Service에서만 직접 사용 (Repository 패턴 불필요)
// 5. 모든 에러는 NestJS 내장 HttpException 서브클래스 사용
// 6. 환경 변수는 ConfigService를 통해서만 접근
// 7. 로깅: NestJS Logger 사용 (this.logger = new Logger(ClassName)), console.log 금지
// 8. 페이지네이션: 기본 size=20, 최대 size=100, class-validator로 제한

// Controller 패턴 — raw data만 반환 (ResponseTransformInterceptor가 ApiResponse<T>로 자동 래핑)
@Get(':id')
@UseGuards(SessionAuthGuard)
async getVulnerability(
  @Param('id') id: string,
): Promise<VulnerabilityDetail> {
  return this.vulnerabilityService.findById(id);
}
```

**로깅 가이드:**

- 모든 로그는 `NestJS Logger` 클래스를 사용한다 (`this.logger = new Logger(ClassName.name)`).
- `console.log` 사용을 금지한다.
- 로그 레벨: 개발 모드 `debug`, 운영 모드 `info` (ConfigService로 분기).
- 에러 로그에는 반드시 **컨텍스트 정보**를 포함한다:
  ```typescript
  this.logger.error(
    `Scan failed: ${scanId}`,
    error.stack,
    'ScanProcessor',
  );
  ```
- 민감 정보(accessToken, 암호화 키) 로그 출력을 금지한다. 토큰 관련 로그는 마스킹 처리한다 (예: `token: ***${last4}`).

### Frontend (React/TypeScript)

```typescript
// 1. @aegisai/shared 타입을 반드시 import (직접 정의 금지)
// 2. 서버 상태: TanStack Query, 클라이언트 상태: Zustand
// 3. API 함수는 api/ 디렉토리에 집중, 컴포넌트에서 직접 axios 호출 금지
// 4. 로딩/에러 상태 모든 useQuery에서 처리
// 5. 401 처리는 Axios 인터셉터, 일반 에러 토스트는 Query 글로벌 에러 처리 (역할 분리)
// 6. ProtectedRoute는 React Router v6 wrapper component 패턴으로 구현

import type { VulnerabilityDetail } from '@aegisai/shared';

const { data, isLoading, error } = useQuery({
  queryKey: ['vulnerability', vulnId],
  queryFn: () => fetchVulnerability(vulnId),
});
```

#### 핵심 프론트엔드 패턴 구현 예시

```tsx
// apps/web/src/router.tsx
import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { ProtectedRoute } from './components/layout/ProtectedRoute';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { ReposPage } from './pages/ReposPage';
import { ScanPage } from './pages/ScanPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { VulnerabilityDetailPage } from './pages/VulnerabilityDetailPage';

export const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  {
    path: '/',
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'dashboard', element: <DashboardPage /> },
      { path: 'repos', element: <ReposPage /> },
      { path: 'scan', element: <ScanPage /> },
      { path: 'scans/:scanId/vulnerabilities', element: <VulnerabilitiesPage /> },
      { path: 'vulnerabilities/:vulnId', element: <VulnerabilityDetailPage /> },
    ],
  },
]);
```

```tsx
// apps/web/src/components/layout/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();

  if (isLoading) return <div className="flex h-screen items-center justify-center">Loading...</div>;
  if (!user) return <Navigate to="/login" replace />;

  return <>{children}</>;
}
```

```typescript
// apps/web/src/api/client.ts
import axios from 'axios';

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:3000/api',
  withCredentials: true, // 세션 쿠키 전달 필수
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest', // CSRF 보호
  },
});

// 401 인터셉터 — 인증 만료 시 로그인 페이지로 리다이렉트
// ⚠️ /login 페이지에서는 리다이렉트하지 않아 무한루프를 방지한다
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && window.location.pathname !== '/login') {
      window.location.href = '/login';
      return Promise.reject(error);
    }
    return Promise.reject(error);
  },
);
```

```typescript
// apps/web/src/hooks/useAuth.ts
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { AuthUser } from '@aegisai/shared';
import { apiClient } from '../api/client';

export function useAuth() {
  const queryClient = useQueryClient();

  const { data: user, isLoading } = useQuery<AuthUser | null>({
    queryKey: ['auth', 'me'],
    queryFn: async () => {
      try {
        const res = await apiClient.get('/auth/me');
        return res.data.data;
      } catch {
        return null;
      }
    },
    staleTime: 5 * 60 * 1000, // 5분
    retry: false,
  });

  const logout = async () => {
    await apiClient.post('/auth/logout');
    queryClient.setQueryData(['auth', 'me'], null);
    window.location.href = '/login';
  };

  return { user: user ?? null, isLoading, logout };
}
```

## 13. 테스트 전략

| 레이어 | 도구 | 핵심 테스트 |
|--------|------|-------------|
| 단위 (Backend) | Jest | ScanService, MockAnalysisApiClient |
| 통합 (Backend) | Supertest + @testcontainers/postgresql | API E2E, DB/Redis 실제 연동 |
| 단위 (Frontend) | Vitest + RTL | ScanStatusBadge, SeverityBadge, ConsensusScoreBadge |
| API Mocking | MSW | 프론트 개발 중 백엔드 독립 |

**테스트 커버리지 목표:**

| 레이어 | 목표 커버리지 |
|--------|-------------|
| Service (비즈니스 로직) | **80% 이상** (라인 커버리지) |
| Controller | **70% 이상** (주요 경로 + 에러 케이스) |
| 프론트엔드 컴포넌트 | **주요 인터랙션 경로** (커버리지 수치 미강제) |

### 핵심 테스트 케이스

```text
- ScanService: requestScan() → BullMQ Job 등록 확인
- ScanService: 동일 레포 PENDING/RUNNING 중 → 409 반환 확인
- ScanProcessor: executeScan() → Mock API → DB 저장 → DONE 상태 전환
- ScanProcessor: Analysis API 실패 → FAILED 상태 전환 + 에러 메시지 저장
- VulnerabilityService: 필터/정렬/페이지네이션 쿼리 결과 검증
- SessionAuthGuard: 미인증 요청 → 401 반환
- SessionAuthGuard: X-Requested-With 누락 POST/PATCH/DELETE 요청 → 403 반환
- HealthController: GET /api/health → raw JSON 응답 확인 (ApiResponse 래핑 없음)
- RepoController: DELETE /api/repos/:repoId → 204 No Content 확인
- Throttling: POST /api/scans 한도 초과 → 429 반환 확인
- SessionAwareThrottlerGuard: 인증 사용자는 sessionID, 미인증 사용자는 IP 기준 추적 확인
- OAuth 통합 테스트: strategy/service mock 기반 (실제 외부 provider 호출 불필요)
- BullMQ 통합 테스트: @testcontainers/redis 또는 docker compose의 Redis 서비스를 활용하여 BullMQ Worker 통합 테스트를 수행한다.
```

**E2E 시나리오 테스트 (Supertest 기반):**

```text
E2E-01: 인증 → 레포 연동 → 스캔 → 취약점 조회 전체 플로우
  1. mock OAuth 콜백으로 세션 생성
  2. POST /api/repos → 레포 연동
  3. POST /api/scans → 스캔 시작
  4. BullMQ Worker 완료 대기
  5. GET /api/scans/:id → status: DONE 확인
  6. GET /api/scans/:id/vulnerabilities → 취약점 목록 반환 확인
  7. PATCH /api/vulnerabilities/:id/feedback → 피드백 반영 확인

E2E-02: 미인증 접근 차단
  1. 세션 없이 GET /api/repos → 401 확인
  2. 세션 없이 POST /api/scans → 401 확인

E2E-03: 동시 스캔 중복 방지
  1. POST /api/scans → 202 확인
  2. 동일 repoId로 POST /api/scans → 409 확인

E2E-04: 보안/응답 예외 규칙 확인
  1. X-Requested-With 없이 POST /api/scans → 403 확인
  2. GET /api/health → raw JSON 확인 (success/data 래퍼 없음)
  3. DELETE /api/repos/:repoId → 204 No Content 확인
  4. POST /api/scans 반복 호출 → 429 확인
```

**BullMQ 통합 테스트 환경:**
- `@testcontainers/redis` 또는 docker compose의 Redis 서비스를 활용한다.
- 테스트 전: `scan-jobs` 큐를 비운다 (`queue.obliterate({ force: true })`).
- Worker 완료 대기: `QueueEvents`의 `completed` 이벤트를 listen하여 비동기 처리 완료를 확인한다.
- 테스트 후: 생성된 데이터를 정리한다.

---

## 14. 부록

### 부록 A. 환경 변수 목록

| 변수명 | 필수 | 설명 |
|--------|------|------|
| `DATABASE_URL` | ✅ | Prisma PostgreSQL URL |
| `REDIS_URL` | ✅ | BullMQ / Session Redis URL |
| `SESSION_SECRET` | ✅ | express-session 서명 키 |
| `GITHUB_CLIENT_ID` | ✅ | GitHub OAuth App ID |
| `GITHUB_CLIENT_SECRET` | ✅ | GitHub OAuth App Secret |
| `GITLAB_CLIENT_ID` | ✅ | GitLab Application ID |
| `GITLAB_CLIENT_SECRET` | ✅ | GitLab Application Secret |
| `APP_URL` | ✅ | API 서버 Base URL (OAuth 콜백용) |
| `FRONTEND_URL` | ✅ | 프론트엔드 Base URL (CORS origin + OAuth 리다이렉트) |
| `TOKEN_ENCRYPTION_KEY` | ✅ | OAuth 토큰 AES-256-GCM 암호화 키 (32바이트, hex 인코딩된 64자 문자열 또는 base64 인코딩된 44자 문자열로 전달. 예: `openssl rand -hex 32`) |
| `NODE_ENV` | ✅ | `development` / `production` |
| `VITE_API_URL` | - | 프론트엔드에서 사용하는 API 서버 URL (기본: `http://localhost:3000/api`, `apps/web/.env`에 설정) |
| `AI_SERVER_URL` | - | apps/ai FastAPI 서버 URL (기본: `http://localhost:8000`) |
| `USE_INTERNAL_AI` | - | `true` 설정 시 InternalAnalysisApiClient 활성화 |
| `INTERNAL_API_SECRET` | - | NestJS → apps/ai 내부 호출 인증 시크릿 |
| `MODEL_A_ID` | - | 파인튜닝 모델 A 식별자 (apps/ai 환경변수) |
| `MODEL_B_ID` | - | 파인튜닝 모델 B 식별자 (apps/ai 환경변수) |
| `OPENAI_API_KEY` | - | 파인튜닝 모델 호출용 (OpenAI 기반 파인튜닝 시) |
| `GITHUB_APP_WEBHOOK_SECRET` | - | GitHub Webhook HMAC-SHA256 서명 검증 키 [Phase 2] |
| `GITLAB_WEBHOOK_SECRET` | - | GitLab Webhook Secret Token 평문 검증 키 [Phase 2] |

### 부록 A-1. `.env.example` 템플릿

```dotenv
# apps/api/.env.example

# Database
DATABASE_URL=postgresql://aegisai:aegisai@localhost:5432/aegisai

# Redis
REDIS_URL=redis://localhost:6379

# Session
SESSION_SECRET=change-me-to-a-random-string

# GitHub OAuth App
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# GitLab OAuth Application
GITLAB_CLIENT_ID=
GITLAB_CLIENT_SECRET=

# App URLs
APP_URL=http://localhost:3000
FRONTEND_URL=http://localhost:5173

# Token Encryption (AES-256-GCM, 32 bytes)
# 생성 예시: openssl rand -hex 32
TOKEN_ENCRYPTION_KEY=

# Runtime
NODE_ENV=development

# Frontend (apps/web/.env 에 설정)
# VITE_API_URL=http://localhost:3000/api

# AI Server (선택 통합)
AI_SERVER_URL=http://localhost:8000
USE_INTERNAL_AI=false
INTERNAL_API_SECRET=

# AI Model (apps/ai 환경변수)
# MODEL_A_ID=
# MODEL_B_ID=
# OPENAI_API_KEY=

# Webhook Secrets (Phase 2)
# GITHUB_APP_WEBHOOK_SECRET=
# GITLAB_WEBHOOK_SECRET=
```

### 부록 B. 에이전트 개발 체크리스트

```text
시작 전:
[ ] docker compose up -d 실행 → PostgreSQL, Redis 정상 동작 확인
[ ] GitHub OAuth App 생성 → callback: http://localhost:3000/api/auth/github/callback
[ ] apps/api/.env 작성 (부록 A 기준)
[ ] pnpm install → pnpm db:migrate 실행

Phase 1 완료 기준:
[ ] MockAnalysisApiClient를 통한 스캔 E2E 동작
[ ] GET /api/scans/:id → status: "DONE" + 취약점 데이터 (consensusScore 포함) 반환 확인
[ ] GET /api/health → DB·Redis 연결 상태 확인
[ ] 세션 유지 확인 (GitHub 로그인 → /api/auth/me 응답)

선택 통합 검증:
[ ] docker compose up ai-server 실행 → GET http://localhost:8000/health 응답 확인
[ ] USE_INTERNAL_AI=true 설정 시 InternalAnalysisApiClient → apps/ai /analyze 호출 동작 확인

Phase 2 완료 기준:
[ ] /api-docs (Swagger)에서 전체 엔드포인트 테스트 통과
[ ] 미인증 요청 → 401 반환 확인
[ ] Rate Limiting 동작 확인 (초과 시 429 반환)
[ ] GitHub Webhook → PR 이벤트 수신 → 자동 스캔 Job 등록 확인
[ ] POST /api/vulnerabilities/:vulnId/suggest-change → GitHub PR Suggested Changes 생성 확인

Phase 3 완료 기준:
[ ] CORS 정상 동작 확인 (localhost:5173 → localhost:3000)
[ ] GitHub 로그인 → 레포 연동 → 스캔 → 취약점 상세 전체 플로우 브라우저에서 동작
[ ] TASK-17~TASK-22 모든 페이지 및 컴포넌트 정상 렌더링 확인
```

---

*본 문서는 AI 에이전트의 개발 착수를 위한 기술 명세서이다. 구현 중 명세와 괴리가 발생하면 변경 사유를 PR 또는 ADR(Architecture Decision Record)에 기록하고 문서를 업데이트한다.*
