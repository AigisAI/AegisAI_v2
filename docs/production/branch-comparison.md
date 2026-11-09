# 현재 배포본과 dev 비교

2026년 11월 9일 기준으로 원격 `dev`와 현재 배포 소스를 보존한 릴리스 후보를 비교했다. 코드·DB·운영 설정을 변경하거나 실제 병합·재배포하지 않았다. 별도 소스 트리에서 병합 결과만 계산했다.

## 비교 기준과 수치

| 기준 | 커밋 |
| --- | --- |
| 공통 조상 | `3f357371fd6d5a52adbb0ab02b3f2b6fbe3e18ab` |
| 원격 dev | `3154e31505417e95e1a05c50a5d020e8dba4121d` |
| 배포 소스 후보 | `feb7628b76720a6bb43b4a597431484a6205ce8e` |

공통 조상 이후 dev는 338개 커밋·907개 변경 경로, 배포 소스 후보는 5개 커밋·312개 변경 경로가 있다. 두 계열에서 모두 변경한 경로는 115개다. 이전에 기록한 120개는 전체 미커밋 작업 폴더와 원격 변경의 겹침 수로, 이 비교와 범위가 다르다.

`git merge-tree --write-tree --name-only --no-messages` 계산의 실제 충돌 파일은 **106개**다. 브랜치를 이동하거나 working tree에 충돌 표시를 쓰지 않았다. 두 브랜치 끝을 직접 diff했을 때 보이는 대량 삭제는 실제 병합에서 dev 전용 파일을 모두 삭제한다는 뜻이 아니다.

| 충돌 영역 | 파일 수 |
| --- | --- |
| API 코드 | 32 |
| DB 스키마 | 1 |
| API 테스트 | 8 |
| 화면 | 38 |
| 공유 API 계약 | 9 |
| 명세 | 3 |
| 저장소 검증 | 3 |
| 설정·문서·기타 | 12 |

## 무엇이 다른가

| 영역 | 현재 배포 소스 | 원격 dev | 통합할 때 필요한 결정 |
| --- | --- | --- | --- |
| 목표 | 단일 EC2·Tailscale·허용된 계정/조직의 실제 Java 분석 | 003 AI, 004 인프라, 005 배포 계약, 006 SAST 거버넌스 | 현재 비공개 운영과 일반 서비스 기준을 구분 |
| 인증 | 직접 구현한 GitHub state/PKCE, 계정 admission, UserOAuthIdentity, 로그인 토큰 비보관 | Passport GitHub/GitLab, OAuthToken에 암호화한 로그인 토큰 보관, 사용자 tenantId | 계정·테넌트 ID와 세션·인증 데이터 이관 |
| DB | 모델 20개·migration 6개 | 모델 106개·migration 30개 | 현재 데이터를 보존하는 스키마·이력 이관 설계 |
| 스캔 실행 | 호스트 감독 프로세스, Unix 브로커, 전용 gateway, 별도 containerd/gVisor, 실제 세 도구 완료 근거 | signed artifact·attestation·microVM provider 계약 및 검증, 기본 provider는 Unavailable | 실제 실행 어댑터와 해당 격리·qualification 기준 충족 여부 |
| 안전·규칙 관리 | 고정 초기 Java 규칙, bounded fetch, 임대/fencing, 실제 cleanup, 제한된 coverage | rule manifest·semantic policy·canary·kill switch·rollback·서명 검증과 수많은 자격검증 계약 | 즉시 운영 기능과 외부 실행 증거가 필요한 기준을 따로 이관 |
| 근거 저장 | S3/KMS 실연결, 7일 만료·조회 감사·주기 삭제 | accepted evidence·access/deletion authority 등 더 넓은 계약과 저장 구조 | 현재 S3 구현을 dev 계약에 맞추는 검토 |
| AI | DISABLED, 모델 없이 기본 스캔 동작 | 별도 apps/ai 서버·gateway·축소 근거 검증, 기본 HTTP 경로는 deterministic fallback | 자체 모델이나 임시 API는 별도 실제 공급자 연결 필요 |
| 화면·API | production flag로 RuntimeApp, /api/runtime/*, 원시 JSON 및 인증 응답의 csrfToken | 기존 Router/Page, /api/scans 등 계약, success/data 응답 포장, Passport 세션 | 디자인과 데이터 계약을 분리하고 실제 API 어댑터 정리 |
| 배포·확장 | 단일 호스트 Compose/systemd·Tailscale, S3/Secrets Manager 실제 운영 | Kubernetes AI/HPA 정의와 provider-neutral 배포·T056 GO 계약, 기존 Oracle CD도 존재 | 설정 파일 존재와 실제 AWS 적용 사실을 구분 |

모델·커밋·코드 줄 수는 규모를 설명할 뿐 품질·보안·검출률의 우열을 뜻하지 않는다. dev의 큰 변경 중에는 128,151줄짜리 T054 qualification manifest와 32,923줄짜리 golden corpus snapshot도 포함돼 있다.

## 특히 위험한 세 가지 연결점

### 인증과 세션

dev의 AuthService는 Passport에서 받은 로그인 access/refresh token을 암호화해 OAuthToken에 upsert한다. 테넌트 ID는 새 사용자를 만들 때 UUID로 생성하고 User.tenantId에 연결한다. 현재 배포는 GitHub 숫자 ID에서 결정적으로 user/tenant ID를 만들고 UserOAuthIdentity에 인증 주체만 남긴다. 두 쪽 모두 저장소 App 관련 코드가 있으므로 이 차이를 단순히 GitHub App 유무로 설명하면 부정확하다.

같은 이름의 AuthService 파일을 한쪽 것으로 고르면 기존 로그인, 테넌트 매핑과 세션이 다른 쪽 규칙을 기대하는 상태가 된다. 데이터·세션 이관 없이 복사해 교체하지 않는다.

근거: [dev 인증 서비스](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/api/src/auth/auth.service.ts#L31), [배포본 인증 서비스](https://github.com/AigisAI/AegisAI_v2/blob/feb7628b76720a6bb43b4a597431484a6205ce8e/apps/api/src/auth/auth.service.ts#L42).

### DB 이력

공통 migration은 최초 `20260315215651_init` 하나다. dev의 `20260603070000_production_architecture_baseline`과 배포본의 `20260720000000_production_architecture_hardening`은 서로 다른 이름으로 동일한 enum·Tenant 등 기반 구조를 생성한다. 현재 DB에 dev migration을 그대로 적용하면 이미 존재하는 타입·테이블과 충돌할 수 있다. migration 폴더를 합치는 것으로 해결되지 않는다.

dev는 User.tenantId, OAuthToken, SAST 계획·authority·lineage·규칙 lifecycle 모델을 사용한다. 배포본은 UserOAuthIdentity와 자체 dispatch/capability, EvidencePack.deletedAt 등 다른 경로를 사용한다. 운영 DB에 직접 migration을 시험하지 않고 복원된 전용 검증 DB에서 변환을 설계해야 한다.

근거: [dev 스키마](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/api/prisma/schema.prisma), [배포본 스키마](https://github.com/AigisAI/AegisAI_v2/blob/feb7628b76720a6bb43b4a597431484a6205ce8e/apps/api/prisma/schema.prisma).

### 실제 분석 공급자와 화면

dev의 ScanPlaneModule은 ScannerSandboxRuntimeProvider를 UnavailableScannerSandboxRuntimeProvider에 연결한다. 이 provider는 실행 요청에 `SCANNER_SANDBOX_PROVIDER_UNAVAILABLE`와 `No live microVM scanner sandbox provider is installed.`를 반환한다. 따라서 많은 구현·검증 코드가 있다는 사실과 현재 EC2의 실제 분석 실행이 연결돼 있다는 사실을 구분해야 한다. dev의 006 quickstart도 T053~T056 외부 증거와 production Kubernetes rollout의 대기를 명시한다.

근거: [DI 연결](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/api/src/scan-plane/scan-plane.module.ts#L324), [기본 provider](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/api/src/scan-plane/scanner-sandbox-runtime.provider.ts#L41), [006 실행 기준](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/specs/006-production-sast-runtime-design/quickstart.md#L28).

화면도 dev는 RouterProvider와 기존 API client를 사용하고 배포본은 VITE_PRODUCTION_RUNTIME 분기의 RuntimeApp을 사용한다. dev 화면만 그대로 붙이면 /scans와 /runtime/scans, 인증 응답 및 success/data 포장 차이를 동시에 맞춰야 한다. 이것이 실제 API 연결 도중 별도 화면이 생겼던 구조적 이유이며, 디자인 변경이 필수였다는 뜻은 아니다. 기존 디자인을 유지한 채 데이터 계약을 연결했어야 한다.

근거: [dev 화면 진입점](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/web/src/App.tsx#L12), [배포본 화면 분기](https://github.com/AigisAI/AegisAI_v2/blob/feb7628b76720a6bb43b4a597431484a6205ce8e/apps/web/src/App.tsx#L13), [dev 응답 포장](https://github.com/AigisAI/AegisAI_v2/blob/3154e31505417e95e1a05c50a5d020e8dba4121d/apps/api/src/common/interceptors/response-transform.interceptor.ts#L32), [배포 runtime 경로](https://github.com/AigisAI/AegisAI_v2/blob/feb7628b76720a6bb43b4a597431484a6205ce8e/apps/api/src/runtime/runtime.controller.ts#L19).

## 판단과 다음 순서

현재 배포본은 좁은 범위의 실제 운영과 복구 증거가 있고, dev에는 더 넓은 제품 구조·검증·규칙 거버넌스 구현이 있다. 둘 중 한쪽 전체를 버리는 방식으로 통합하지 않는다.

단기 운영은 현재 배포 경로를 유지한다. 통합 전에는 인증·테넌트 ID와 DB 이관, 표준 API 계약 및 원래 화면의 연결, dev의 runtime provider·qualification 요구와 현재 gVisor 운영 예외의 관계를 먼저 결정한다. 그 다음 검증 DB와 비운영 환경에서 adapter와 데이터를 검증하고 실제 전환을 검토한다. EC2 한 대 조건과 AI 선택 사항은 유지한다.

분리한 후보의 CI 성공은 dev 통합 결과에 대한 검증이 아니다. 이번 비교로 mergeable=false의 실제 원인을 확인했으며 자동 병합·강제 덮어쓰기·운영 migration은 수행하지 않았다.
