# 2026-11-10 실제 비공개 Blue/Green 전환·복귀

후속 실제 Canary·자동 복귀 및 최신 전체 상태는 [Canary 운영 기록](./2026-11-10-canary-checkpoint.md)을 따른다. 아래 값은 각 단계의 근거다.

최종 확인: 2026-11-10 22:13 KST. 기존 EC2 한 대에서 실제 비공개 서비스
API 버전을 전환하고 되돌렸다. 원래 서명된 화면은 그대로 사용한다.
이 범위의 G1 검증이며 일반 서비스 자격, UI 변경 배포, Canary 또는 전체 H2
완료를 의미하지 않는다. 이전 G3/G4 근거는 [앞선 운영 기록](./2026-11-10-rollout-scaling-checkpoint.md)이다.

## 현재 상태

앱 소스는 `3edc8c72a69b1927fedad5fccb558f94f7bd824f`, 실제 API/web 이미지도
그 서명 릴리스를 유지한다. 변경된 Git 선언 커밋은
`35fd0fd87c77bf0281e004edeed92a5b1b682ff1`이며 Argo Synced/Healthy다.
정상 ingress와 API/web 각1 Ready, HPA min1/max2로 복원했다. 검증용
`api-blue-green` Rollout과 `web-bg` Deployment는0개이며 실행 경로는 보존했다.
관리 도구 소스는 `90c532140a20d45c97fb7cc2ca65542b24f948e9`,
[CI42821861630](https://github.com/AigisAI/AegisAI_v2/actions/runs/42821861630)가 통과했다.
[PR368](https://github.com/AigisAI/AegisAI_v2/pull/368)은 미병합 draft다.

## 실제 구현과 책임 분리

- Argo Rollouts1.10.2의 CRD 파일 해시와 amd64 이미지 digest를 고정했다.
  전용 `aegisai-rollouts` namespace의 컨트롤러는 앱 namespace 하나만 감시한다.
  메모리96MiB·CPU250m·읽기 전용 파일시스템·제한된 임시 공간을 적용했고 재시작은0회다.
- 앱/Argo Secrets, 기존 API Deployment·Service 쓰기, Pod 생성, nodes,
  clusterrolebindings 접근이 실제 RBAC 확인에서 거부됐다. 동적 ReplicaSet 쓰기는
  자신의 Rollout 소유 객체로 admission에서 제한했다. CRD 설치는 root가 수행한다.
- 기존 API/web 서비스에 `delivery=deployment` 선택자를 추가했다. 현재 Ready Pod를
  먼저 표시하고 Git 차트로 같은 표시를 유지해, 원래 서비스가 preview에 요청을
  보내지 않도록 분리했다. Root가 원하는 Rollout 버전을 선택하고 컨트롤러가 별도
  active/preview Service를 전환한다. 기존 Argo 차트는 이 두 Service를 관리하지 않는다.
- 원래 서명된 웹 이미지의 별도 `web-bg`가 active API를 사용한다. 바깥 비공개
  allowlist·헤더·경로·Tailscale 설정은 유지하고, 준비 확인 후 기존 ingress upstream만
  전환했다. 기존 API/web은 계속 복귀 대상으로 실행했다.
- 검증 중에만 기존 HPA를1개로 제한해 전체 API 최대3·웹 최대2를 유지했다.
  종료 후 profile을0개로 줄인 것을 확인한 뒤 원래 HPA1~2를 복원했다.
  별도 root 타이머와 finally 복구가 원래 ingress·운영 상태·HPA를 복구한다.

이전 f340 API는 프로세스별 요청 제한을 사용하므로 이 경로에서는 정확히1개로
실행했다. 해당 버전의 다중 복제 안전성을 새로 인증한 것이 아니다. 현재 정상
3ed 버전은 기존 공유 Redis 요청 제한을 유지한다.

## 실제 전환 근거

| 단계 | 실제 결과 |
| --- | --- |
| 초기 active | 3ed API, Pod hash `6567664d5d` |
| preview | f340 API, Pod hash `7576cf4b48`, 준비 확인12.597초 |
| 실제 active 승격 | f340 API로 전환, 관측0.404초, 실제 소유자 세션 응답5.006ms |
| 실제 버전 복귀 | 3ed API로 복귀, 관측0.407초, 실제 소유자 세션 응답13.372ms |
| 종료 복구 | 원래 ingress·GitOps 운영 경로·HPA1~2, 검증 profile0개 확인 |

두 버전은 각각 승인된 기존 API digest74430c…/36fc2d…다. 매 실행 전 서명·출처·
검사 유효기간을 신뢰된 검증기로 다시 확인하고 실제 이미지 존재/CRI pinned 상태도
확인했다. 서비스 선택자와 실제 EndpointSlice의 Ready Pod UID·이미지·주소가 일치해야
전환으로 기록했다. 준비 완료뿐 아니라 초기 active hash/Healthy 동기화까지 기다린다.
전환 표의 시간은 이 제한된 실제 관측값이며 연속 무손실·p95·SLO 보장이 아니다.
관측한 health 응답은 모두200이었고, 양쪽 API와 실제 ingress에서 기존 소유자 세션이
성공했다. 합성 세션이나 새 로그인은 만들지 않았다.

초기 준비 시도에서는 첫 active hash가 설정되기 전에 다음 버전을 올려 컨트롤러가
초기 배포로 취급하는 조건을 발견했다. 외부 서비스 경로를 바꾸기 전에 검증이
거부됐고 원래 상태로 복구했다. 실제 active hash/관측 세대까지 기다리도록 수정한
후 승인 대기·수동 승격·복귀를 확인했다. 실패 시도를 성공 근거로 계산하지 않는다.

앞선 선택자 적용 첫 시도에서 health 확인 한 건이 실패해 Git을 자동 복구했다.
당시 도구는 실패 응답 코드를 보관하지 않아 특정 HTTP 오류로 단정하지 않는다.
종료 전5초 유예와 최소 준비5초를 추가하고 실패 표본 보관도 보완했다. 재적용은
16.588초에 완료됐고 관측 health는 모두200이었다.

## 보존 확인과 증거

최종 복귀 뒤 실제 기존 세션·저장소5개·완료 결과·암호화 근거 조회, 비인증/타 테넌트
차단 및 완료 작업 미재실행을 다시 확인했다. 사용자1·연동1·저장소5·스캔1·도구 실행3·
근거1이며 AI는 DISABLED다. 새로운 스캔·SQL 마이그레이션·DB 복원은 실행하지 않았다.
원래 HTML SHA256은 `ec08d4be8be19fba1a5ddfea0ca09983c9606c6ee16224a7ab70f7088f4bdf29`다.
최종 가용 메모리는4556MiB, 디스크 여유는약13GiB였다. 독립 gVisor·추가 컴퓨팅 금지·
공개 ingress 금지·runtime IAM 확대 금지를 유지했다.

원본은 서버 root 전용 `kubernetes/blue-green/acceptance-result.json`, 실행별
`blue-green/run-*/recovery-result.json`, `rollouts/installation-result.json`,
`gitops/promotion-35fd0fd87c77.json`이다. 로컬 통합 증거는
`output/deploy/bluegreen367-result.json`이다. 비밀 값은 이 문서에 포함하지 않는다.

다음은 실제 가중치 Canary와 자동 중단/복귀다. 제한된 AWS OIDC·Rollouts의 최종
GitOps 프로필 관리 책임을 포함한 전체 H2, H1 재현·복구, H4 비동기 분산 추적도 남았다.
일반005/006 T053–T056은 NOT_QUALIFIED 그대로다.
