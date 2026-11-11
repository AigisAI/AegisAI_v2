# 남은 작업과 적용 범위

2026-11-11 운영 기준. 기존 단일 EC2의 private 범위에서 G1~G4와 H2~H4를 실제 검증했다.
H1에서 제어 영역의 외부 복구를 통과했고 전체 호스트 재현과 프로젝트 실청구 검증이 남아 있다.
[스캔 추적과 운영 릴리스](./scan-tracing-release.md) · [제어 영역 복구와 AWS 배포 인증](./aws-control-backup-delivery-gate.md)

## 현재 운영 상태

- 기존 EC2 한 대·암호화50GiB·Tailscale 비공개 접속이다. 추가 컴퓨팅·공개 ingress·runtime IAM 확대는 하지 않는다.
- 소스 `4d3d542737ad79be521321f7cc228e59d0d203b1`, 릴리스 `ec2-runtime-20261111-073640`가 실제 API/web을 실행한다. [전체 CI42978789014](https://github.com/AigisAI/AegisAI_v2/actions/runs/42978789014)가 통과했다.
- Helm/Argo Git 선언 커밋은 `62176ad54e02bb1c76c39646e427c60f4438d014`이며 Synced/Healthy다. API/web 각1 Ready, API HPA min1/max2다. PR 자체의 dev/main 병합은 별개다.
- 기존 계정·연동·저장소·스캔 결과를 보존했다. 새 릴리스의 기존 로그인 사용자 경로에서 실제 완료와 실패를 확인했다. 완료 스캔에서 도구 실행 3건과 활성 증거 1건이 추가됐다.
- 원래 화면 HTML, 6개 마이그레이션 이력과 독립 containerd/gVisor 격리 경계를 보존했다.
- AI는 DISABLED로 서비스가 동작한다. 자체 로컬 모델이 목표이며 API 임시 대체·미연결을 허용한다. AI는 advisory-only다.
- 기존 Docker 릴리스 `ec2-runtime-20261109-135802`은 복귀본이다. `shared/candidate-release`와 실제 접속 책임 `operator/application-traffic.json`을 구분한다.

## 여덟 필수 항목

| ID | 상태 | 실제 근거와 남은 일 |
| --- | --- | --- |
| G1 Blue/Green | private API 범위 검증 완료 | Argo Rollouts·별도 active/preview·실제 비공개 경로 전환/복귀0.404/0.407초·양 버전의 기존 로그인 응답·원래 화면/데이터 및 HPA 복구 확인. UI 변경 배포와 일반 자격은 별도 |
| G2 Canary | private API 범위 검증 완료 | 실제 후보 요청6/60→30/60→60/60·정상180건 모두200·native Prometheus 판정3건 성공. 실제 후보502 6건에 native 분석 실패/자동 abort,17.235초 뒤100/0·후속10건 모두 정상. 실제 세션 보존 |
| G3 Kubernetes RollingUpdate | private 범위 검증 완료 | 실제 정상 교체16.988초·불량 준비 후보 제외/자동 Git 복구55.125초·이전 이미지 복귀10.074초·재전환10.023초. 관측 health 모두200 |
| G4 HPA | private API 범위 검증 완료 | 실제 CPU에 따른1→2→1·수집기 유실 시2 유지·최대2·실제 기존 세션 및 데이터 보존. 공유 Redis 요청 제한19→18→17→16이 두 API에 걸쳐 적용됨 |
| H1 Terraform IaC | 부분 완료 | 기존12자원 import/no-op·state 암호화/잠금·drift·삭제 거부·격리 state 백업/복구 plan 확인. 최신 SQLite 백업을 격리된 K3s API에서 복구해 Git 리비전·이미지 참조·암호화 Secret 확인. 기존 S3 암호화 백업에서 제어 영역을 실제 복구함. 전체 호스트 재현·관리 범위·비용 검증은 남음 |
| H2 GitOps/CD | private 범위 검증 완료 | 제한된 Argo·Helm 실제 동기화·3.631초 drift 복구·객체 재생성·검증된 Git/image 승격·실패/복귀 확인. 운영 커밋과 동일한 AWS OIDC 검증 성공을 요구한 서명 릴리스가 Argo CD로 실제 전환됨. Argo CD 기본 Service와 Rollouts의 전략 Service를 분리하고 HPA의 API replica 관리 필드를 실제 확인함 |
| H3 공급망 보안 | private API/web 범위 완료 | CI 실제 이미지 검사·SBOM·출처·서명 및 누락/변조/정책 위반 거부, Kubernetes digest admission. 타사 전체 이미지까지 완료했다는 뜻은 아님 |
| H4 관측·분산 추적 | private 범위 검증 완료 | Grafana·Loki·Prometheus·Alloy·Tempo, HTTP trace·지표·로그·실제 Slack 장애/복구 확인. 정상 스캔 3개 도구와 증거 발행, 소스 제한 차단을 동일 요청의 Tempo span·Loki 로그로 추적함. Prometheus 스캔 요청 지표 실제 조회 |

실행 기준은 [기존 계획](../reports/2026-11-07-production-deployment-plan.md) 4/G·4/H·8·9절이다.
그 계획의 날짜별 상태 문장은 당시 기록이며, 최신 완료 여부는 위 표를 따른다.
전체 호스트 복구와 프로젝트 실청구 검증은 남아 있다.

## 운영 보완과 최종 확인

- 운영 승격은 서명·출처·검사 신선도를 재검증한다. 검사24시간/DB48시간 만료 후보를 예외 승격하지 않는다.
- Blue/Green·Canary 검증 profile은0개로 보존했고 기존 API/web 정상 경로·HPA1~2를 복원했다. 일반 Service의 delivery 선택자가 preview를 제외한다.
- 실제 복귀 중 드러난 미사용 이미지 GC 문제를 수정했다. 현재·직전 승인 이미지 쌍을 실제 CRI pinned로 보존하고, 이미지 부재 시 Git 변경 전에 거부한다. 복구 뒤 실제 이전/최신 이미지 전환을 통과했다.
- CoreDNS 64MiB 한도·부팅 후 재적용 타이머를 설치했다. 운영 DNS 조회와 별도 K3s API에서 실제 SQLite 복구가 통과했다. 기존 S3 버킷의 외부 복구와 AWS OIDC 접속도 확인했다. [11월 11일 복구 기록](./2026-11-11-control-recovery-checkpoint.md) · [외부 복구와 OIDC 운영 기록](./aws-control-backup-delivery-gate.md)
- Rollouts/K3s의 생성 이벤트 파싱 경고가 관측됐으나 실제 정상/실패 reconciliation은 완료됐다. 해당 경고의 원인 분석은 운영 보완 항목이다.
- 바깥 Nginx의 이전 이미지와 잔여 보안/보관 예외는 별도 검토 대상이다. 현재 공급망 검증 완료를 모든 구성 요소의 취약점 부재로 표현하지 않는다.
- F-3/F-5/F-6의 장애별 탐지/복구·성공 트래픽 기준 성능·실제 비용과 F-8 최신 사용자 경로를 정리해야 한다. HPA 시험의 대부분429 응답을 성공 처리량으로 제시하지 않는다.
- 누락됐던 AWS 운영자 자동 갱신 작업을 재등록해 실행 중임을 확인했다. 기존 사용자 자동 재연결과 5분 상태 확인으로 유지한다. Windows 재인증 PC는 로그인·온라인이어야 한다. 앱 EC2 역할 갱신은 독립적이며 장기 AWS 키를 추가하지 않았다.
- 사용자가 보존하도록 한 이전 EBS·스냅샷은 삭제하지 않는다. 과거 미암호화 사본·비활성 로컬 비밀 및 감사/보관 자동화 예외는 숨기지 않는다.
- EC2 외 S3·Secrets Manager·KMS·기존 EBS/스냅샷 사용료가 발생한다. 자원 상한을 월 청구 상한으로 표현하지 않는다.

## 유지할 경계

일반 005/006 T053–T056은 NOT_QUALIFIED다. 이 승인된 단일 호스트 범위를 고가용성·별도 노드 격리·
공개 다중 테넌트 준비로 확대하지 않는다. DB·Redis·큐·브로커·감독 프로세스·스캐너는 HPA로 복제하지 않는다.
고객 코드 실행·빌드·패키지 설치·직접 업로드는 금지다. 로그인과 SCM 자격증명은 분리한다.

문서만 바뀌면 링크·사실·범위만 확인한다. 코드 변경은 영향 경로와 의미 있는 정상/실패 검증을 수행하고,
변경 없는 전체 테스트·실스캔·복원을 불필요하게 반복하지 않는다. 전체 확장 완료는 남은 필수 조건까지 충족한 뒤 판단한다.
