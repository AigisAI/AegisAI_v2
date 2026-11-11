# 비공개 운영 스캔 추적

2026-11-11 서명된 API·웹·브로커와 호스트 감독 프로세스를 기존 단일 EC2에 반영했다. 운영 Git 리비전은 `62176ad54e02bb1c76c39646e427c60f4438d014`, 이미지 소스는 `4d3d542737ad79be521321f7cc228e59d0d203b1`이다. Argo CD는 Synced/Healthy였고, 전환 중 헬스 응답은 모두 200이었다. 운영 HTML의 SHA-256이 이전과 일치했다. [서명 이미지 검증](https://github.com/AigisAI/AegisAI_v2/actions/runs/42978789014) · [배포 OIDC 검증](https://github.com/AigisAI/AegisAI_v2/actions/runs/42981647016)

## 관측과 운영 한계

HTTP 요청에서 발급한 trace ID와 부모 span ID를 새 dispatch의 내부 감사 이벤트에 남긴다. 브로커는 동일 테넌트·스캔·dispatch에 해당하는 값만 감독 프로세스에 전달한다. 감독 프로세스는 큐 대기, 브로커 할당, 소스 전달, 스캐너 실행, 정리와 결과 발행·거부를 고정된 이름의 span으로 기록한다. OTLP 전송은 사설 Alloy로 한정하며 저장소 이름, 파일 경로, 소스, 토큰과 결과 본문을 span 속성에 쓰지 않는다.

운영에서 실제 소스 제한 차단을 확인했다. HTTP 요청, 큐, 브로커, 감독 프로세스, 소스 전달 오류, 정리, 거부가 동일한 Tempo trace에 있고 부모 관계와 오류 상태가 일치했다. 같은 trace ID와 HTTP span ID로 Loki 요청 로그를 찾았다. 소스 크기 제한에서 거부된 작업의 실행 도구와 증거 파일은 0건이었다.

기존 운영 프로필은 Java 정적 스캔과 소스 크기·개수 제한을 적용한다. 운영 화면에서 실행한 `AigisAI/AegisAI`의 `master` 스캔이 17.339초에 완료됐다. OpenGrep·Trivy·Syft는 모두 COMPLETED였고 활성 증거 1건이 생성됐다. Tempo에서 HTTP 요청, 큐 대기, 브로커 할당, 소스 전달, 세 도구, 정리와 증거 발행의 부모 관계 10개 span을 확인했다. Loki 요청 로그에서 동일한 trace와 HTTP span ID가 일치했다. Prometheus의 스캔 생성 2xx 누적 카운터 4건을 조회했다. 이 카운터는 운영 API가 받아들인 요청을 집계하며 최종 스캔 결과는 Tempo와 DB에서 확인한다.
