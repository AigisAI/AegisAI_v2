# 2026-11-11 제어 상태 복구와 CoreDNS 운영 확인

11:13 KST에 기존 EC2에서 `post-canary-20261110-135209`의 SQLite와
서버 토큰으로 별도 K3s API를 복구했다. 작업 시작부터 복구 결과를 확인하기까지
7.531초였다. 복구 API는 별도 네트워크의 루프백 주소에만 바인딩했다.
스케줄러와 워크로드 에이전트를 끈 상태에서 실제 저장 데이터를 읽었다.

- Argo Application의 Git 리비전 `35fd0fd87c77bf0281e004edeed92a5b1b682ff1`과
  API·웹 Deployment의 서명 이미지 참조가 당시 운영 상태와 일치했다.
- Blue/Green·Canary Rollout의 복제 수가 각각 0인 상태를 복구했다.
- SQLite에 암호화된 상태로 저장된 Argo Redis Secret을 복구 API가 읽었다.
  명령은 Secret의 유형만 출력했다.
- 운영 API·웹 Pod UID와 Compose 컨테이너 ID가 전후 일치했다. 운영 health는
  HTTP200이었고 스캔 감독기·브로커도 계속 실행 중이었다.
- 첫 실행은 이미 기동한 K3s의 Pod 경로를 초기 설치 검사에서 중복으로 판정했다.
  복구용 자원 검사와 별도 네트워크 확인으로 바꾼 뒤 성공했다.

실제 CoreDNS 메모리 한도는 170MiB로 돌아가 있었다. 64MiB 한도와 32MiB
요청값을 재적용했고 CPU는 요청 50m, 한도 200m으로 맞췄다. 새 Pod가 Ready가
된 뒤 기존 Pod가 종료되도록 `maxUnavailable: 0`을 설정했다. 운영 API Pod에서
`kubernetes.default.svc.cluster.local` 조회가 성공했다. 부팅 후와 매분 확인하는
`aegisai-coredns-limits.timer`를 활성화했다.

복구 절차는 [운영 명세](../../specs/009-private-single-host-kubernetes/control-recovery.md)에
있다. 실제 복구 원본은 서버의 root 전용 `control-recovery-result.json`이다.
H1에는 전체 호스트 재구성, 외부 백업으로부터의 복구, Terraform 관리 범위와
비용 검증이 남아 있다. H2와 H4의 상태는 [남은 작업](./remaining-work.md)에서 추적한다.
