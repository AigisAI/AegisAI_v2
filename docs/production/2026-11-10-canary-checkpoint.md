# 2026-11-10 실제 Canary 분배·자동 중단·복귀

최종 확인: 2026-11-10 22:52 KST. 기존 EC2 한 대의 실제 비공개 서비스에서
API Canary를 적용해 측정했다. 원래 서명된 화면·DB·SCM·독립 gVisor는 유지했다.
[앞선 Blue/Green 기록](./2026-11-10-blue-green-checkpoint.md)과 함께 승인된
private 범위의 G1~G4 실증을 완료한다. 일반005/006 자격은 NOT_QUALIFIED다.

## 실행 기준과 실제 정상 분배

실행 전에10%→50%→100%, 단계별60건·최대2RPS·요청 제한5초, HTTP200,
실제 분배 오차10%p 이내·클라이언트 p95≤1초를 정했다. Root가 실제 버전별
카운터와 준비된 EndpointSlice/Pod UID·서명 이미지가 일치하는지 확인하고
승인 대기를 해제한다. 그 뒤 native AnalysisRun이 실제 Prometheus에서 후보 요청≥3,
후보5xx 비율≤1%, 후보 histogram p95≤1초를 모두 통과해야 다음 단계로 진행한다.
이전 실행의 값을 섞지 않도록 실제 라우터 인스턴스를 고정하고 빈 지표/오류/NaN으로
승격하지 않는다. 가짜 지표·수동 중단을 자동 복귀 근거로 쓰지 않는다.

| 후보 비중 | 실제 정상 버전 요청 | 실제 후보 요청 | HTTP 응답 | 클라이언트 p95 |
| --- | --- | --- | --- | --- |
| 10% | 54 | 6 | 60건 모두200 | 8.14ms |
| 50% | 30 | 30 | 60건 모두200 | 6.29ms |
| 100% | 0 | 60 | 60건 모두200 | 5.23ms |

실제 native AnalysisRun 세 건이 Successful이었다. Prometheus의 후보 누적 요청은
6→36→96, 오류 비율은0이었다. Histogram p95 추정값은 약95ms였다. 이 값은
버킷 기반 추정치이며 위 표의 클라이언트 측정값과 구분한다. 총180건은 통제된 실제
읽기 전용 health 요청이다. 실제 사용자 전체 트래픽이나 처리량/SLO 보장이 아니다.

기준 버전은 서명 소스3edc8c72a69b, 후보는 기존 승인 소스f340a441f366이다.
모든 실행 전 신뢰된 검증기로 서명·출처·검사 신선도와 실제 CRI pinned 상태를
다시 확인했다. 두 버전은 각각1개로 실행하며 이전 f340의 다중 복제를 인증하지 않는다.
정상 승격 후100% 후보 경로에서 실제 소유자 로그인 세션도 성공했다.

## 실제 오류와 자동 복귀

후보 Pod 자체는 Ready로 유지하고 그 후보 Service의 대상만 닫힌3001 포트로
바꿨다. 해당 Pod로의 임시3001 통신만 허용해 실제 연결 거부가 나도록 했고,
복구 후 이 예외와 잘못된 포트를 제거했다. 서비스·데이터·고객 코드는 바꾸지 않았다.

60건 중 정상 버전54건은200, 후보6건은 실제502였다. 실제 Prometheus가
후보 오류 비율1.0을 반환해 native AnalysisRun `api-canary-b987b58d4-2-2`가
Failed가 됐다. Argo가 스스로 abort하고 가중치를100/0으로 되돌렸다.
판정 뒤 컨트롤러·root 투영·라우터에 자동 복귀가 관측되기까지17.235초였다.
수동 abort 명령은 실행하지 않았다. 이후 실제10건은 정상 버전10·후보0,
모두200이었다. 오류나 지표를 위조하지 않았다.

## 구현과 현재 책임

- 공식 Docker Traefik3.7.17의 amd64 digest와 TraefikService CRD 해시를 고정했다.
  upstream3.7.18은 더 최신이지만 선택 당시 공식 Docker 태그가 아직 없었다.
  3.7.17을 최신 upstream으로 표현하지 않는다. 외부 TLS/ACME·플러그인·압축·인증
  middleware·자동 사용량 전송·Kubernetes/Docker 자동 탐색은 사용하지 않는다.
- 라우터는 토큰 없이96MiB/250m, 읽기 전용 filesystem, 제한된 임시 공간,
  restricted PodSecurity와 default-deny로 실행한다. 호스트 포트·NodePort·공개
  진입점은 없다. 앱 웹→라우터→허용 API 및 내부 지표 수집 경로만 연다.
- Rollouts가 명명된 stable/candidate Service 선택자와 TraefikService 가중치를
  관리한다. Root publisher가 정확한 두 서비스·포트·0~100 합계와100% 조건을
  검증하고, 고정 목적지만 포함한 설정을 read-only ConfigMap으로 투영한다.
  임의 URL·포트·서비스·가중치를 거부하는 범위별 검증도 통과했다.
- 기존 Argo CD Deployment 차트와 별도 profile을 분리했다. 실제로 로드된 라우터
  설정과 자식 서비스 카운터를 확인했다. 라우터 자체는 Kubernetes/SCM/AWS 자격증명을
  받지 않는다. Root publisher는 기존 root kubeconfig만 사용하고 CPU10%/메모리96MiB다.
- native 분석은 특정 내부 Prometheus만 조회한다. 임의 AnalysisRun 생성은 실제
  admission에서 거부했다. 앱/Argo Secrets·원래 Deployment/Service·노드·cluster RBAC
  권한은 추가하지 않았다. AWS IAM이나 공개 인바운드도 변경하지 않았다.
- 검증 동안만 기존 HPA를1개로 제한해 총 API≤3·웹≤2를 유지했다. 독립10분 복구
  타이머와 finally 경로는 원래 ingress를 먼저 복구한 뒤 profile Pod를0개로 줄이고
  HPA1~2를 복원한다. 두 시나리오 모두 원래 경로로 복구한 뒤 종료했다.

## 최종 보존·복구 확인

현재 소스는 그대로 `3edc8c72a69b1927fedad5fccb558f94f7bd824f`, 활성 Git 선언은
`35fd0fd87c77bf0281e004edeed92a5b1b682ff1`이며 Argo Synced/Healthy다.
원래 ingress와 API/web 각1 Ready, HPA min1/max2, Blue/Green·Canary profile0개,
잘못된 후보 포트 복원과 임시 방화벽 예외 삭제를 확인했다. 다른 전략을 동시에
기본 경로로 섞지 않고 실제 실행한 별도 경로를 보존한다.

기존 웹 세션이 만료된 준비 시도는 변경 전에 중단했다. 소유자가 다시 GitHub로
로그인한 뒤, 검증은 합성 세션 없이 새 실제 세션으로 진행했다. 세션 유효기간이나
보안 정책을 늘리지 않았다. AWS 운영자 인증은 독립적인 자동 갱신이며 마지막 STS도
기존 goodtu02로 성공했다. AWS OIDC CI 역할은 아직 만들지 않았다.

최종 확인13:49:39UTC에 실제 세션·저장소5개·완료 결과·암호화 근거 조회 및
비인증/타 테넌트 차단·완료 작업 미재실행이 통과했다. 사용자1·연동1·저장소5·
스캔1·도구 실행3·근거1을 유지했다. 새 스캔·SQL 마이그레이션·DB 복원은 실행하지
않았고 AI는 DISABLED다. HTML SHA256도 기존 ec08d4be…4bdf29와 같다.

최종 가용 메모리4372MiB, 디스크 여유약11GiB였다. 기존50GiB·한 EC2·독립 gVisor와
무거운 스캔1건 한도를 유지했다. 최신 control SQLite·토큰·암호화 설정·선언 상태와
publisher unit도 root 전용 암호화 디스크에 백업하고 SQLite quick_check를 통과했다.
`control-backups/post-canary-20261110-135209`는 로컬 백업이며 실제 전체 복구나
외부 DR 검증으로 표시하지 않는다.

## 소스와 증거

운영 도구 소스는 `1454fc04326e56bf69486116ce6fcbe32d01099e`,
[CI42826638514](https://github.com/AigisAI/AegisAI_v2/actions/runs/42826638514)가 성공했다.
[PR370](https://github.com/AigisAI/AegisAI_v2/pull/370)은 미병합 draft다.
라우터/투영기는 f8cf91a 설치본이며 controller/분석 설정은 b525ea5 설치본이다.
서버 root 전용 `kubernetes/canary/acceptance-normal.json`, `acceptance-fault.json`,
각 `run-*/recovery-result.json`, router/control installation 결과가 원본이다.
로컬 통합 증거는 `output/deploy/canary369-result.json`이다.

남은 필수 항목은 H1 전체 IaC 복구·재현, H2 제한된 AWS OIDC 및 전체 GitOps/CD
관리 책임, H4 큐/브로커/작업/스캐너까지의 실제 분산 추적이다. 타사 전체 이미지 보안·
control-plane 재시작/DNS 제한 지속성·최종 복구/비용 등의 잔여 운영 조건도 계속 추적한다.
