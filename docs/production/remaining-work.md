# 남은 작업과 적용 범위

최종 갱신: 2026-11-10 22:52 KST. 실제 운영 근거는
[Canary 운영 기록](./2026-11-10-canary-checkpoint.md)을 우선한다.
사용자가 필수 지정한 G1~G4·H1~H4는 계속 완료 조건이다. 현재 승인된 private 범위에서
G1·G2·G3·G4·H3를 실제 검증했으며, 나머지 세 항목은 전체 완료 전이다.

## 현재 운영 상태

- 기존 EC2 한 대·암호화50GiB·Tailscale 비공개 접속이다. 추가 컴퓨팅·공개 ingress·runtime IAM 확대는 하지 않는다.
- 소스 `3edc8c72a69b1927fedad5fccb558f94f7bd824f`, 릴리스 `ec2-runtime-20261110-114154`가 실제 API/web을 실행한다. [전체 CI42807277712](https://github.com/AigisAI/AegisAI_v2/actions/runs/42807277712)가 통과했다.
- Helm/Argo Git 선언 커밋은 `35fd0fd87c77bf0281e004edeed92a5b1b682ff1`이며 Synced/Healthy다. API/web 각1 Ready, API HPA min1/max2다. PR 자체의 dev/main 병합은 별개다.
- 사용자1·연동1·저장소5·스캔1·도구 실행3·근거1을 유지했다. 최신 버전에서 기존 실제 세션·저장소·완료 결과·암호화 근거 조회와 비인증/타 테넌트 거부를 확인했다.
- 원래 화면 HTML은 동일하다. 데이터6개 마이그레이션·독립 containerd/gVisor·무거운 스캔1건을 보존했다. 새 스캔·SQL·운영 DB 복원·대화형 OAuth는 반복하지 않았다.
- AI는 DISABLED로 서비스가 동작한다. 자체 로컬 모델이 목표이며 API 임시 대체·미연결을 허용한다. AI는 advisory-only다.
- 기존 Docker 릴리스 `ec2-runtime-20261109-135802`은 복귀본이다. `shared/candidate-release`와 실제 접속 책임 `operator/application-traffic.json`을 구분한다.

## 여덟 필수 항목

| ID | 상태 | 실제 근거와 남은 일 |
| --- | --- | --- |
| G1 Blue/Green | private API 범위 검증 완료 | Argo Rollouts·별도 active/preview·실제 비공개 경로 전환/복귀0.404/0.407초·양 버전의 기존 로그인 응답·원래 화면/데이터 및 HPA 복구 확인. UI 변경 배포와 일반 자격은 별도 |
| G2 Canary | private API 범위 검증 완료 | 실제 후보 요청6/60→30/60→60/60·정상180건 모두200·native Prometheus 판정3건 성공. 실제 후보502 6건에 native 분석 실패/자동 abort,17.235초 뒤100/0·후속10건 모두 정상. 실제 세션 보존 |
| G3 Kubernetes RollingUpdate | private 범위 검증 완료 | 실제 정상 교체16.988초·불량 준비 후보 제외/자동 Git 복구55.125초·이전 이미지 복귀10.074초·재전환10.023초. 관측 health 모두200 |
| G4 HPA | private API 범위 검증 완료 | 실제 CPU에 따른1→2→1·수집기 유실 시2 유지·최대2·실제 기존 세션 및 데이터 보존. 공유 Redis 요청 제한19→18→17→16이 두 API에 걸쳐 적용됨 |
| H1 Terraform IaC | 부분 완료 | 기존12자원 import/no-op·state 암호화/잠금·drift·삭제 거부·격리 state 백업/복구 plan 확인. 전체 관리 범위·코드 기반 재현/최종 복구·보관과 비용 근거가 남음 |
| H2 GitOps/CD | 부분 완료 | 제한된 Argo·Helm 실제 동기화·3.631초 drift 복구·객체 재생성·검증된 Git/image 승격·실패/복귀 확인. Rollouts/HPA 필드 책임 충돌 검증과 제한된 AWS GitHub OIDC 역할은 미완료 |
| H3 공급망 보안 | private API/web 범위 완료 | CI 실제 이미지 검사·SBOM·출처·서명 및 누락/변조/정책 위반 거부, Kubernetes digest admission. 타사 전체 이미지까지 완료했다는 뜻은 아님 |
| H4 관측·분산 추적 | 부분 완료 | Grafana·Loki·Prometheus·Alloy·Tempo, HTTP trace·지표·로그·실제 Slack 장애/복구 확인. 요청→큐/시도→브로커/작업→스캐너/결과의 정상·실패 상관 추적은 남음 |

실행 기준은 [기존 계획](../reports/2026-11-07-production-deployment-plan.md) 4/G·4/H·8·9절이다.
그 계획의 날짜별 상태 문장은 당시 기록이며, 최신 완료 여부는 위 표를 따른다.
Rollouts의 최종 GitOps 관리 책임과 제한된 AWS OIDC, H4 비동기 추적을 진행한 뒤 H4 비동기 추적·H1 복구/재현·허용된 H2 AWS 연동 및
통합 복구/비용 근거를 닫는다. 권한이 필요한 잔여 사항을 이미 승인된 runtime IAM 확대처럼 해석하지 않는다.

## 운영 보완과 최종 확인

- 운영 승격은 서명·출처·검사 신선도를 재검증한다. 검사24시간/DB48시간 만료 후보를 예외 승격하지 않는다.
- Blue/Green·Canary 검증 profile은0개로 보존했고 기존 API/web 정상 경로·HPA1~2를 복원했다. 일반 Service의 delivery 선택자가 preview를 제외한다.
- 실제 복귀 중 드러난 미사용 이미지 GC 문제를 수정했다. 현재·직전 승인 이미지 쌍을 실제 CRI pinned로 보존하고, 이미지 부재 시 Git 변경 전에 거부한다. 복구 뒤 실제 이전/최신 이미지 전환을 통과했다.
- Kubernetes 재시작 시 기본 DNS 자원 제한 재적용과 제한된 복구 절차를 최종 점검한다. 최신 control-state 로컬 백업/SQLite 검사는 통과했으며 실제 전체 복구와 구분한다. 과거 부팅/DB 복구 근거만으로 최신 전체 복구를 완료하지 않는다.
- Rollouts/K3s의 생성 이벤트 파싱 경고가 관측됐으나 실제 정상/실패 reconciliation은 완료됐다. 최종 H2 호환성 점검에서 경고 원인도 정리한다.
- 바깥 Nginx의 이전 이미지와 잔여 보안/보관 예외는 별도 검토 대상이다. 현재 공급망 검증 완료를 모든 구성 요소의 취약점 부재로 표현하지 않는다.
- F-3/F-5/F-6의 장애별 탐지/복구·성공 트래픽 기준 성능·실제 비용과 F-8 최신 사용자 경로를 정리해야 한다. HPA 시험의 대부분429 응답을 성공 처리량으로 제시하지 않는다.
- AWS 운영자 인증은 기존 사용자 자동 재연결과 5분 확인/갱신으로 유지한다. Windows 재인증 PC는 로그인·온라인이어야 한다. 앱 EC2 역할 갱신은 독립적이며 장기 AWS 키를 추가하지 않았다.
- 사용자가 보존하도록 한 이전 EBS·스냅샷은 삭제하지 않는다. 과거 미암호화 사본·비활성 로컬 비밀 및 감사/보관 자동화 예외는 숨기지 않는다.
- EC2 외 S3·Secrets Manager·KMS·기존 EBS/스냅샷 사용료가 발생한다. 자원 상한을 월 청구 상한으로 표현하지 않는다.

## 유지할 경계

일반 005/006 T053–T056은 NOT_QUALIFIED다. 이 승인된 단일 호스트 범위를 고가용성·별도 노드 격리·
공개 다중 테넌트 준비로 확대하지 않는다. DB·Redis·큐·브로커·감독 프로세스·스캐너는 HPA로 복제하지 않는다.
고객 코드 실행·빌드·패키지 설치·직접 업로드는 금지다. 로그인과 SCM 자격증명은 분리한다.

문서만 바뀌면 링크·사실·범위만 확인한다. 코드 변경은 영향 경로와 의미 있는 정상/실패 검증을 수행하고,
변경 없는 전체 테스트·실스캔·복원을 불필요하게 반복하지 않는다. 전체 확장 완료는 남은 필수 조건까지 충족한 뒤 판단한다.
