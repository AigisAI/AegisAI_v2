# 배포와 검증 기록

배포일은 2026년 11월 8일이다. 사람이 읽는 시각은 Asia/Seoul이며, 원본 로그와 서버 JSON의 ISO 시각은 UTC다. 예를 들어 원본의 12:48:30Z는 한국 시각 21:48:30이다. 아래 내용은 지정된 배포에 대한 확인 결과이며 이후 릴리스에 자동 승계하지 않는다.

## 배포 출처

| 구성 | 배포 식별자 | 파일 수 | 원본 SHA-256 |
| --- | --- | --- | --- |
| API와 최초 화면 | ec2-runtime-20261108-122119 | 266 | `66e0c49897d81797fcd77d605dd98897dfa8c5f35518d69b59d53614c1c3732e` |
| 호스트 분석 감독 프로세스 | host-worker-20261108-122846.tar.gz | 별도 묶음 | `024d980e856dff855cc3ddf6a90720fee76454f113ffa95f79f556cbd460a3c4` |
| 디자인 복원 화면 | ec2-runtime-20261108-124735 | 275 | `8d49489993a3b2252dab758be5d144ab05a8b1c4d006ece80a7a3075ff40a69d` |

Git 기준 커밋은 `a8e51eb26d082fefe420cb150b43815f09fbbcf7`이며 실제 배포는 미커밋 변경을 포함한 dirty snapshot이다. 이 커밋만 checkout해서 배포 코드가 완전히 재현된다고 표현하지 않는다. 화면 전용 교체 전에 API·공유 코드·의존성 입력의 동일성을 확인했다. 현재 API 식별자와 화면 식별자가 다른 것은 의도된 구성이다.

부팅 비밀 로딩·백업·접근 전환 등 일부 운영 파일은 개별 설치됐다. 위 소스 아카이브 하나가 모든 최신 호스트 상태를 표현하지 않는다. 서버 운영 기록과 설치 파일 해시를 함께 보관해야 한다. 문서 자체는 배포 후 사실에 맞게 갱신될 수 있으며 과거 아카이브를 덮어쓰지 않는다.

## 확인 결과와 범위

| ID | 확인 내용 | 결과 | 근거와 한계 |
| --- | --- | --- | --- |
| V01 | 실제 GitHub 로그인·저장소 연결 | 확인 | 사용자 휴대폰 로그인, 기존 사용자·조직 연동·선택 저장소 5개 |
| V02 | 실제 비공개 Java 저장소 분석 | 확인 | 세 도구 COMPLETED, 작업 SUCCEEDED, AI DISABLED, coverage LIMITED |
| V03 | 분석 종료 후 정리 | 확인 | 소스 RAM 디렉터리 비어 있음, sandbox와 gateway 없음 |
| V04 | 암호화 근거·테넌트 조회·감사 | 확인 | SSE-KMS 실제 객체 읽기와 감사 기록 |
| V05 | 근거 만료 처리 | 확인 | 별도 운영 점검 객체로 동일 정리 코드 실행, 실제 객체 삭제 확인 |
| V06 | 관리형 비밀을 이용한 재부팅 | 확인 | operator cache 없이 비밀 로딩·앱·브로커·감독 프로세스 복구 |
| V07 | 재시작 후 기존 결과 유지 | 확인 | 스캔·실행 3개·근거가 읽히며 완료 작업 재실행 없음 |
| V08 | 외부 암호화 백업 복원 | 확인 | 업로드·다운로드 해시 일치, 고유한 검증 DB에 복원, 행 수 일치 |
| V09 | 비공개 진입점 차단·복원 | 확인 | 루트 503→200, 미로그인 runtime 401, 기존·ops API 404 |
| V10 | 기본 검증 6종 | 통과 | lint, test, typecheck, build, Prisma validate, runtime-layout 검사 |
| V11 | 대상 환경 검증 | 통과 | 배포 HTTP 3개·SQL 16개·native 7개, 관리형 저장 관련 SQL 5개 |
| V12 | 디자인 복원 화면 | 자동 확인 통과 | 웹 테스트 63개·타입·수정 파일 lint·이미지 빌드·실제 경로 응답 |
| V13 | 사용자가 실제 완료 결과 확인 | 확인 | 최초 운영 화면에서 확인, 이후 디자인 복원에 대한 별도 시각 승인 미기록 |
| V14 | 브라우저에서 새 스캔 버튼 실행 | 미확인 | 실제 저장소 분석은 검증된 사용자에 대한 운영 서비스 호출로 시작 |
| V15 | GitHub hosted CI·AWS 자동 CD | 미확인·미구현 | CI 설정은 존재하지만 해당 스냅샷의 hosted 실행 성공이나 AWS CD는 주장하지 않음 |
| V16 | 브라우저에서 근거 다운로드 | 미확인 | 실제 S3·서비스 계층 근거 읽기와 감사 기록은 V04로 확인, 브라우저 다운로드 전체 경로와 구분 |

V02의 발견 항목은 0개였다. 실제 분석 경로가 완료된 증거이며 검출률, 오탐률, 모든 취약점의 부재를 입증하지 않는다. 도구의 양성·음성 검사는 별도 통제된 fixture로 수행했다.

V08의 일치 항목은 마이그레이션 6개, 사용자 인증 연결 1개, SCM 연동 1개, 저장소 연결 5개, 스캔 1개, 발견 항목 0개, 도구 실행 3개, 근거 1개다. 단순 행 수 확인 외에 기존 실제 스캔과 근거 읽기는 V07로 확인했다. 전체 호스트 재구축, 임의 시점 복구, 정량 RTO/RPO 입증으로 확대 해석하지 않는다.

## 근거 파일 위치

| 확인 | 로컬 기록 | 서버 기록 |
| --- | --- | --- |
| 릴리스 검증 | output/deploy/managed-runtime-candidate-deploy.log, final-*.log | operator/acceptance/workspace-validation.json |
| 실제 스캔 | output/deploy/actual-private-java-scan.log | operator/acceptance/live-scan-result.json |
| 물리 정리 | output/deploy/actual-scan-cleanup-proof.log | 점검 당시 명령 결과, 상시 무결성 증명은 아님 |
| 저장소·만료 | output/deploy/managed-runtime-live-checks.log | retention 상태와 감사 기록 |
| 백업 복원 | output/deploy/first-offsite-backup-restore.log | operator/offsite-backup-status.json |
| 부팅 복구 | output/deploy/managed-boot-recovery.log | operator/acceptance/restart-result.json |
| 접근 롤백 | output/deploy/private-access-rollback-check.log | operator/private-ingress-status.json |
| 디자인 수정 | output/deploy/restored-design-{tests,types,lint,deploy}.log | operator/web-release.json |

서버 상대 위치의 기준은 `/opt/aegisai/`다. 원본 운영 로그는 일반 공개 문서의 첨부물로 간주하지 않으며 자격증명·개인 정보·비공개 저장소 정보가 없는지 확인한 요약만 포트폴리오에 사용한다. 로그가 로컬에 있다는 사실과 Git에 추적·보존된다는 사실은 다르다.

## 문서화 시점의 상태 재확인

2026년 11월 8일 22:00:34 한국 시각에 읽기 전용으로 확인했다. 앱 4개와 브로커가 healthy였고 실패한 systemd unit은 없었다. 스캐너 ready=true, busy=false, AI=DISABLED였으며 근거 정리 상태도 healthy였다. 루트 디스크는 약 6.6GiB 여유였다. 이 수치는 순간 관측값이며 용량 벤치마크나 운영 상한 보장이 아니다.

## 다음 검증 규칙

기능·DB·분석 경계가 바뀌면 해당 검증과 릴리스 게이트를 다시 수행한다. 화면만 바뀌고 API·공유 계약·의존성이 같으면 웹 범위만 확인한다. 문서만 바뀌면 링크·주장과 근거·파일 변경 범위를 확인하며 스캔이나 복원·부하 시험을 불필요하게 반복하지 않는다.

## 문서 정리 이력

2026년 11월 9일에 현재 운영 문서 묶음과 진입점·명세·과거 기록의 연결을 정리했다. 이는 위 11월 8일 배포·관측 기록의 날짜를 바꾸거나 새 런타임 검증으로 간주하는 작업이 아니다. Markdown 링크·코드 블록·제어 문자, 세 배포 아카이브의 해시·구성 파일 수를 확인하고 로컬 검토 기록을 output/deploy/documentation-review.json에 남긴다. 앱 코드·실행 설정 변경, 재배포, 비밀 회전·삭제, 새 실제 스캔·복원 시험은 수행하지 않았다.
