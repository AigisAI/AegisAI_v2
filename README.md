# AegisAI

GitHub 저장소의 Java 코드와 선언된 의존성을 검사하는 보안 분석 서비스다.
현재는 기존 AWS EC2 한 대에서 Tailscale을 통한 비공개 실배포로 운영하며,
실제 Opengrep·Trivy·Syft 실행과 결과 저장을 확인했다. AI는 꺼져 있다.

[실배포 문서](./docs/production/README.md)에서 현재 구조, 검증 근거,
운영·복구 절차와 남은 작업을 확인할 수 있다.

## 현재 범위

- 허용된 GitHub 사용자와 선택된 조직 저장소만 접근한다.
- 로그인 전용 App과 저장소 접근 App을 분리한다.
- PostgreSQL 작업 큐, 임대·fencing, 제한된 재시도로 작업을 처리한다.
- 별도 containerd/gVisor에서 네트워크 없이 고정 분석 도구를 실행한다.
- 정규화 결과와 LIMITED coverage를 저장하고 S3/KMS 근거를 7일 보관한다.
- Secrets Manager 기반 부팅, 실제 저장소 분석, 소스 정리, 백업 복원과 재시작을 확인했다.

실제 동시 분석은 한 건이며 단일 호스트 장애가 전체 서비스에 영향을 준다.
Kubernetes·HPA·Blue/Green·Canary·AWS 자동 CD·일반 다중 테넌트·HA는 미적용이다.
GitLab, 공개 웹훅, PR 댓글, PDF 및 AI 추론도 현재 운영 범위가 아니다.
AI의 최종 목표는 자체 로컬 모델이며 임시 API 또는 AI 비활성 상태를 허용한다.
미구현 기능이나 예시 데이터를 운영 기능으로 표시하지 않는다.

## 문서와 실행 순서

1. [AGENTS.md](./AGENTS.md)
2. [002 canonical quickstart](./specs/002-production-scan-architecture/quickstart.md)
3. [003 production runtime quickstart](./specs/003-production-runtime/quickstart.md)
4. [실배포 아키텍처](./docs/production/architecture.md)
5. [배포 검증 기록](./docs/production/release-evidence.md)
6. [운영 절차](./deploy/aws-ec2/OPERATIONS.md)
7. [남은 작업](./docs/production/remaining-work.md)

002는 아키텍처 기준과 진입점이며 실제 런타임 구현은 더 좁은 003이 담당한다.
제품 기준 원본은 Desktop의 Security Scan SaaS Final Specification.docx다.
[001](./specs/001-aegisai-mvp-foundation/)과 [spec 2.2](./spec%202.2.md)는
역사적 MVP 참고 자료다. 우선순위와 보안 경계는 AGENTS.md를 따른다.

## 저장소 구성

| 위치 | 역할 |
| --- | --- |
| apps/api | NestJS API, Prisma, 인증·연동·작업·결과·데이터 보호 |
| apps/web | React/Vite 화면, 실제 런타임과 개발 화면 분리 |
| apps/scanner | 소스 게이트웨이, 감독 프로세스, 고정 분석 도구 실행 |
| packages/shared | 공유 API 계약과 타입 |
| deploy/aws-ec2 | 현재 AWS 운영·배포·복구 자산 |
| deploy/oracle | 기존 Oracle dev/demo 경로, AWS 실배포와 별도 |
| specs/002-production-scan-architecture | canonical 아키텍처 기준 |
| specs/003-production-runtime | 실제 런타임 명세와 작업 현황 |
| docs/production | 현재 운영 설명과 증거·후속 작업 |
| docs/reports | 날짜별 구현 기록과 이전 설계 |
| test | 전용 PostgreSQL·네이티브 권한·런타임·workflow 검증 |

## 개발과 검증

Node.js 요구 범위는 package.json을 따르며 운영 이미지는 Node.js 22다.
Corepack/pnpm workspace를 사용한다. 환경 예시는 [.env.example](./.env.example),
[API 예시](./apps/api/.env.example), [웹 예시](./apps/web/.env.example)에 있다.

```powershell
corepack pnpm install
corepack pnpm dev
```

개발 서버가 운영 SCM 권한이나 운영 DB를 자동으로 사용한다고 가정하지 않는다.
원문 업로드, 고객 코드 실행·빌드·패키지 설치는 금지한다.
공유 계약은 packages/shared에 두고 세션·CSRF·throttling을 유지한다.

전체 코드 릴리스의 기본 검증은 002 quickstart의 여섯 명령이다.
003의 SQL/native 추가 검증은 반드시 전용 검증 DB에서 수행한다.
중간 화면 수정은 영향 범위 검증을 적용하고, 문서 수정은 링크·사실·변경 범위를
확인한다. 운영 스캔이나 복원을 문서 변경 때문에 반복하지 않는다.

현재 배포는 미커밋 변경을 포함한 소스 스냅샷이다. 로컬·대상 이미지 검증과
GitHub hosted CI 성공은 다르다. 기존 GitHub Actions CD의 Oracle 대상 설정을
AWS 자동 배포 성과로 소개하지 않는다.

## GitHub 규칙

[GitHub conventions](./docs/github-conventions.md)를 따른다.
dev는 통합, main은 릴리스 준비 브랜치다. feat/fix/refactor/release/hotfix에
이슈 번호를 붙이고 커밋은 type: description 형식으로 작성한다.
이슈와 PR 제목은 동일하게 유지한다. 관련 없는 사용자 변경은 한꺼번에 커밋하지 않는다.
