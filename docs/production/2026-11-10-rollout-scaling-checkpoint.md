# 2026-11-10 실제 RollingUpdate·HPA 운영 기록

최신 확인: 2026-11-10 21:36 KST. 기존 EC2 한 대의 비공개 실운영 범위다.
일반 005/006 T053–T056 자격은 NOT_QUALIFIED 그대로이며 고가용성·별도 노드
격리·공개 서비스 준비를 완료한 기록이 아니다.

## 현재 실행본과 관리 책임

| 항목 | 실제 값 |
| --- | --- |
| 앱 소스 | `3edc8c72a69b1927fedad5fccb558f94f7bd824f` |
| 앱 릴리스 | `ec2-runtime-20261110-114154` |
| 전체 CI | [42807277712](https://github.com/AigisAI/AegisAI_v2/actions/runs/42807277712), 성공 |
| 배포 태그 | [deploy/private-ec2-20261110-114154](https://github.com/AigisAI/AegisAI_v2/tree/deploy/private-ec2-20261110-114154) |
| Git 선언 상태 | `c33a9cfe60883f281bfb619bd4dee273760ba252`, Argo Synced/Healthy |
| API digest | `sha256:74430c44c5f3748796a4528d2cc29754088213c93b6a956671bd1da4927e7563` |
| 웹 digest | `sha256:bbea19b8cb6ced6d8fa3e965ceb223648491f62c22c58d6bf8c68d2c61567b8c` |
| 실행 상태 | API 1 Ready·웹 1 Ready, HPA min1/max2 |
| 운영 도구 | `4fa3b8aff7455e23a982b42179e1aa547f07ad69`, [범위별 CI42816852096](https://github.com/AigisAI/AegisAI_v2/actions/runs/42816852096) 성공 |

앱 소스는 PR #364의 실제 전체 검증을 통과한 merge commit이다. 이 기록은 PR이나
dev/main이 병합됐다는 뜻이 아니다. 루트 운영자가 검증된 소스·이미지와 정확한 Git
커밋을 선택하고, Helm/Argo CD가 명명된 API/web 자원만 관리한다. HPA가 API replicas를
소유하며 Argo는 해당 필드를 무시한다. 운영 비밀·catalog·EndpointSlice·DB·Redis·브로커·
독립 gVisor 스캐너는 앱 차트가 관리하지 않는다.

기존 Docker 복귀본 `ec2-runtime-20261109-135802`은 보존했다. 기존
`shared/candidate-release`는 그 Docker 복귀본을 뜻한다. 현재 트래픽은 별도 root 전용
`operator/application-traffic.json`이 기록한다. Compose 배포 진입점 세 곳은 Kubernetes
운영 중 변경 전에 거부된다.

## G3: 실제 정상 교체·준비 실패 제외·이미지 복귀

- 새로운 서명 소스로 정상 Deployment RollingUpdate가 16.988초에 완료됐다.
  API/web 모두 maxSurge1/maxUnavailable0, readiness/startup과 종료 처리를 유지했다.
- Git `c68f4a1479341e0d223d312b86017dd5aee99dcb`의 준비 실패 후보는 실제 새 Pod가
  준비되지 않았으며 기존 Ready API가 계속 서비스했다. 운영 승격기가 실패를 감지해
  기존 Git으로 자동 복구했다. 총 55.125초이며 Deployment 자체의 자동 롤백으로
  표현하지 않는다.
- 이전 이미지 복귀의 첫 시도는 kubelet의 미사용 이미지 정리 때문에
  `ErrImageNeverPull`이 발생했다. 승격기가 정상 버전으로 자동 복구했다.
  서명 허용 목록만으로 실제 이미지 가용성이 보장되지 않는 결함이었다.
- 승인된 현재·직전 두 이미지 쌍을 CRI 삭제 방지 상태로 고정했다. 사라진 이전
  아카이브는 신뢰된 서명·출처·검사 유효기간을 다시 검증하고 복구했다. 다음 승격은
  대상 이미지의 실제 존재와 CRI pinned 상태를 확인하기 전에는 Git을 변경하지 않는다.
  오래된 자체 고정만 해제하며 vendor 이미지나 스캐너 저장소는 정리하지 않는다.
- 보완 후 Git `36e5991b0b62de8da49c766cb12ac0483f8fd5a8`의 이전 f340 이미지로
  실제 복귀가 10.074초, 최신 c33/3ed 이미지로 재전환이 10.023초에 완료됐다.
  두 경로 모두 관측한 health 요청은 HTTP200이었다. 연속 무손실이나 정량 SLO의
  보증으로 확대하지 않는다.

승격 시마다 신선한 H3 검증을 다시 한다. 보관·재시작 가능과 정상 승격 자격은 다르다.
현재 정책의 24시간 검사·48시간 DB 유효기간을 넘는 후보에 새 승격 예외를 주지 않는다.

## G4: 실제 HPA와 다중 API 안전성

TLS 검증된 Metrics API와 autoscaling/v2를 사용한다. 실제 CPU가 1m에서48m로 올라
150m 요청의32%가 됐고, 목표25%에서 API가 29.37초에1→2 Ready로 늘었다.
측정 수집기만 잠깐 중단했을 때 FailedGetResourceMetric이 나타났고2개를 유지했다.
수집기를 복구하고 부하를 제거한 후 정확히1개로 줄었다. 최대2개와 안정화·증감
한도를 유지했으며 노드나 데이터/스캐너를 늘리지 않았다.

이 제한된 측정은5195건 중200응답240건·429응답4955건이었다. 성공 트래픽 처리량
벤치마크로 제시하지 않는다. 초기 API별 메모리 요청 제한은 복제 수만큼 허용량이
늘어나는 문제가 있어 공유 Redis 원자적 제한으로 교체했다. 전체 응답 제한시간과
연결/큐 상한, Redis 장애 시503 차단을 실제 Redis를 사용하는 CI에서 검증했다.

최신 운영 이미지 두 API에서 기존 소유자의 실제 로그인 세션을 확인했다. 같은
`/auth/me` 경로를 두 Pod에 번갈아 요청하자 남은 허용량이19→18→17→16으로 이어졌다.
검증 뒤 임시 min2를 min1로 되돌리고 실제1 Ready를 확인했다. 세션을 새로 합성하거나
실스캔·마이그레이션·운영 DB 복원을 실행하지 않았다.

## 데이터·화면·격리 확인

최종 재전환 뒤 기존 실제 소유자 세션·저장소5개·완료 결과·암호화 근거 다운로드가
성공했다. 비인증 조회와 타 테넌트 근거 조회는 거부됐고 완료 작업은 재실행되지 않았다.
사용자1·연동1·저장소5·스캔1·도구 실행3·근거1을 유지했다. AI는 DISABLED다.
웹 HTML SHA256은 기존과 같은
`ec08d4be8be19fba1a5ddfea0ca09983c9606c6ee16224a7ab70f7088f4bdf29`다.

최종 관측에서 가용 메모리는4667MiB, 루트 디스크 여유는 약13GiB다. 이는 관측값이며
전체 부하 용량 보증은 아니다. 기존 EC2 한 대·50GiB, 비공개 접속·독립 gVisor·동시
무거운 스캔1건을 유지했다. 새 AWS 컴퓨팅·공개 ingress·runtime IAM은 추가하지 않았다.

## 증거와 잔여 조건

로컬 통합 증거는 `output/deploy/rolling365-result.json`이며 실제 Pod/health 표본을
포함한다. 서버의 root 전용 `kubernetes/gitops/promotion-*.json`,
`resource-metrics/hpa-acceptance-result.json`, `resource-metrics/shared-throttle-result.json`,
`image-retention-result.json`에서 원본을 확인한다. 비밀 값은 이 문서에 포함하지 않는다.

이로써 승인된 private 범위의 G3·G4 실증을 완료했다. H3도 private API/web 범위에서
유지된다. G1 Blue/Green·G2 Canary는 아직 실제 적용 전이다. H2는 drift·객체 재생성·
Git/이미지 승격·복귀까지 실제 확인했지만 Rollouts 소유권과 제한된 AWS OIDC 역할이
남았다. H1 전체 코드 재현·최종 복구, H4 실제 큐/브로커/스캐너까지의 분산 추적도
남아 있다. 권한 확대 없는 현재 승인 범위를 지키며 이 조건들을 완료 처리하지 않는다.
