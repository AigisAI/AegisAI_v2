# 비공개 실배포 운영과 장애 대응

대상은 현재 단일 EC2·허용된 사용자·선택된 조직 저장소다. 명령은 해당 EC2의
운영자가 실행한다. 서버 스크립트는 /opt/aegisai/operator에 있다.
[현재 구성](../../docs/production/architecture.md)과
[검증 기록](../../docs/production/release-evidence.md)을 먼저 확인한다.
한국 시각은 Asia/Seoul이며 원본 JSON의 Z 시각은 UTC다.

## 상태 확인

다음은 읽기 전용 점검이다. 환경 파일·개인 키·전체 Docker 설정은 출력하지 않는다.

```sh
sudo docker ps --format '{{.Names}}:{{.Status}}'
sudo systemctl --failed --no-legend
sudo systemctl is-active aegisai-runtime-secrets aegisai-private-broker aegisai-scan-supervisor
sudo cat /opt/aegisai/scanner/catalog/current.json
sudo cat /run/aegisai-retention/status.json
sudo cat /opt/aegisai/operator/offsite-backup-status.json
sudo systemctl list-timers 'aegisai-*' --all
df -h /
curl --fail --silent https://aegisai-aws.tailaca7d2.ts.net/api/health
```

앱 api/web/postgres/redis와 별도 브로커는 healthy, 실패 unit은 없어야 한다.
API health의 database·sessionStore가 up이어야 한다. 스캐너 catalog는 60초
이내이며 ready=true여야 새 스캔을 받을 수 있다. busy=true는 진행 중 표시다.
Retention은 healthy이고 30분 이내여야 한다. DB 갱신은 48시간 신선도,
fetch egress 정책은 24시간 신선도를 요구한다. 상태가 오래됐다고 파일 시각만
수정해 통과시키지 않는다.

healthz는 비공개 진입점 설정을 설명할 뿐 전체 분석 가능 여부가 아니다.
API·Redis가 살아 있어도 스캐너/저장소/retention이 실패하면 새 분석은 차단된다.
기존 결과는 가능한 범위에서 조회할 수 있다.

## 주기 작업과 알림

| 작업 | 실행 설정 | 실패 시 확인 |
| --- | --- | --- |
| 근거 삭제 | 부팅 2분 후, 이후 약 15분, 지연 30초 가능 | evidence-retention unit과 상태 파일, 삭제 지연 |
| 취약점 DB | 부팅 15분 후, 이후 6시간, 지연 5분 가능 | vuln-db-refresh unit, 현재 DB 시각·해시·디스크 |
| GitHub egress 갱신 | 부팅 10분 후, 이후 6시간, 지연 5분 가능 | fetch-egress-refresh unit, 기존 허용 규칙의 신선도 |
| DB 백업 | 매일 한국 시각 03:15, 지연 5분 가능, Persistent | database-backup unit, 최근 성공 시각과 S3 객체 |

```sh
sudo journalctl -u aegisai-scan-supervisor -u aegisai-private-broker --since '30 minutes ago' --no-pager
sudo journalctl -u aegisai-evidence-retention -u aegisai-database-backup --since '24 hours ago' --no-pager
```

원시 소스나 자격증명이 없는 요약만 공유한다. 현재 경보는 journald와 상태 기반
새 분석 차단이다. 외부 호출·메신저·메일 알림은 구성하지 않았다. 백업 실패 때
이전 성공 JSON이 남을 수 있으므로 JSON의 성공 표시만 보지 말고 unit 실패와
성공 시각을 함께 확인한다. 26시간 이상 백업 성공이 없으면 운영자가 장애로
조사한다는 기준이며 자동 외부 알림이 구현됐다는 뜻은 아니다.

근거는 7일 만료 후 즉시 읽기를 거절한다. 주기 삭제는 재시도와 orphan 정리를
포함한다. 24시간을 넘는 삭제 지연은 경보와 새 분석 차단 대상이다.
S3 lifecycle만으로 정시 삭제를 보장한다고 표현하지 않는다.

취약점 DB 갱신은 디스크 여유 3GiB 조건과 두 스냅샷 보관 제한이 있다.
여유 부족 시 검토 없이 볼륨·현재 이미지·복구 사본을 삭제하지 않는다.
로컬 백업의 자동 정리와 외부 디스크 경보는 후속 과제다.

## 접근 차단과 작업 중지

장애·권한 의심·전체 코드 배포 전 먼저 사용자 요청을 차단한다.

```sh
sudo python3 /opt/aegisai/operator/activate-private-ingress.py pause
sudo systemctl stop aegisai-scan-supervisor.service
sudo systemctl is-active aegisai-scan-supervisor.service
```

정상 pause는 루트 503과 기존 로그인 확인 화면만 남긴다. 중지에는 현재 작업
정리가 포함되며 완료까지 기다린다. 브로커는 정리·폐기 확인에 필요하므로
게이트웨이를 실행 중인 채 먼저 강제 종료하지 않는다. CLI 프로세스만 죽여서
분석 환경이 남지 않게 한다. 소스 tmpfs, scanner sandbox와 transient gateway가
사라졌는지 작업별로 확인한다. dispatch·감사 이력을 지우지 않는다.

```sh
sudo find /run/aegisai-scan-jobs -mindepth 1 -maxdepth 1 -print
sudo /opt/aegisai/scanner/nerdctl ps -a
sudo systemctl list-units --all 'aegisai-fetch-*.service'
```

성공적으로 정리된 유휴 상태에서는 작업 디렉터리와 분석 컨테이너가 없고 실행
중인 일회성 gateway unit도 없어야 한다. 출력이 있으면 이유를 조사하며
폴더를 재귀 삭제하거나 containerd 전체를 초기화하지 않는다.
상태 진단은 별도 백업·스캔을 새로 만들지 않는다.

## 원인별 대응

| 증상 | 대응 | 하지 않을 작업 |
| --- | --- | --- |
| Tailscale 주소 접근 불가 | 클라이언트 연결, tailscaled·Serve, 인스턴스 상태 확인 | 공개 inbound·Funnel을 임시로 열기 |
| 로그인·세션 오류 | api/Redis 상태, 콜백과 admission, Auth secret 확인 | demo 세션 생성, OAuth 비밀을 채팅에 전달 |
| ready=false | catalog·retention·DB·egress·브로커 원인을 확인 | 상태 파일 시각 조작, runc로 격리 우회 |
| 권한 폐기 확인 불가·연동 suspended | 상류 토큰 폐기/만료와 브로커 이력 조사, 통제된 재인증 | DB 상태만 ACTIVE로 바꿔 자동 재개 |
| 소스 크기·미지원 Java 입력 실패 | 화면 실패 사유와 현재 지원 범위를 안내 | 한도를 조용히 높이거나 누락을 정상 완료로 표시 |
| 저장소 또는 AWS 접근 오류 | 역할·서비스 상태·권한·쿼터 확인, bounded retry 종료 상태 조사 | operator cache를 앱에 마운트 |
| DB/Redis 오류 | 새 작업 차단 유지, 서비스와 볼륨 상태 확인 | 메모리 저장소로 대체, 운영 볼륨 삭제 |
| 근거 만료·삭제 실패 | 만료 조회 차단 유지, 삭제 unit·S3 권한·지연 확인 | expiry 연장이나 expired 파일 직접 노출 |

## 재개

원인을 해결하고 정리가 확인된 후 재개한다.

```sh
sudo systemctl start aegisai-scan-supervisor.service
sudo cat /opt/aegisai/scanner/catalog/current.json
sudo python3 /opt/aegisai/operator/activate-private-ingress.py promote
```

promote는 지정된 실제 스캔·부팅·백업·검증 보고서와 현재 준비 상태를 검사한다.
현재 미로그인 runtime은 401, legacy/ops 경로는 404가 정상이다. 특정 API
오류를 없애기 위해 허용 경로를 넓히지 않는다. pause→promote 접근 복원은
실제로 확인했으며 모든 이전 이미지 버전으로의 롤백을 확인한 것은 아니다.

## 전체 코드 배포와 화면 전용 배포

전체 후보는 소스 해시, 검토된 변경 범위, 전용 검증 DB, 현재 백업과 migration
호환성을 준비한다. pause와 작업 중지 후 deploy-candidate.sh를 실행한다.
이 스크립트는 API/web 검증과 백업·migration·교체를 수행하지만 ingress를
자동 공개하지 않고, 이전 호스트 worker bundle도 자동 재개하지 않는다.
검토한 설치 스크립트로 일치하는 host bundle을 적용하고 복구·준비 상태를
확인한 뒤 재개한다. 실패하면 차단 상태로 원인을 조사한다.

화면 전용 deploy-web.py는 API·공유 코드·의존성이 이전 API 릴리스와 같을 때만
허용한다. web-release.override.yaml과 web-release.json에 독립 버전을 기록한다.
앱 health 실패 시 이전 web 이미지로 복귀하는 코드가 있으며, root restore는
override를 포함한다. 전체 릴리스 성공 시 별도 override를 폐기한다.

이전 API 이미지가 현재 DB 스키마와 호환된다고 가정하지 않는다. 데이터
migration을 되돌리기보다 접근 차단 후 호환성 검토와 forward repair를 우선한다.
API·DB·브로커·호스트 bundle의 조합은 하나의 복구 대상으로 취급한다.

## 백업과 복원

백업은 기존 인스턴스 역할로 DB dump를 압축하고 S3/KMS에 신규 객체로 저장한 뒤
다시 내려받아 해시를 확인한다. 역할에 백업 Delete 권한은 없고 기존 키
덮어쓰기도 bucket 조건으로 차단된다. S3 lifecycle은 14일이다. 로컬 사본의
디스크 수명주기는 별도 미완료 항목이다.

필요한 운영 점검 창에만 다음을 실행한다. 새 백업·저장 요청이 발생하며 전용
검증 PostgreSQL 컨테이너가 사전에 준비돼 있어야 한다.

```sh
sudo python3 /opt/aegisai/operator/backup-current-data.py --verify-restore
```

현재 스크립트는 유휴 상태에서 비교할 것을 요구한다. 고유한 검증 DB에만
복원하고 삭제하며 운영 DB에는 복원하지 않는다. 최신 일일 보고서는
restoreVerified=false일 수 있다. 이는 그날 전송·해시만 확인했다는 뜻이며
과거 복원 검증 기록을 별도로 보존해야 한다. 이 명령을 단순 문서 수정 때
반복하지 않는다.

실제 운영 DB 복원은 현재 구현이 자동 수행하는 절차가 아니다. 접근·worker를
차단하고 현재 원본 보존, 대상 DB 검토, 호환 릴리스와 외부 복구 접근 수단을
준비한 뒤 별도 점검 창에서 진행한다. 전체 호스트 재구축과 정량 RTO/RPO는
미검증이며, 최초 소규모 DB 복원 시간을 목표 복구 시간으로 쓰지 않는다.

## 재부팅과 비밀 관리

유휴 상태의 실제 재부팅은 확인됐다. native AWS CLI와 인스턴스 역할이
Docker보다 먼저 DB 암호를 root 전용 RAM에 준비하고 API·브로커는 관리형
비밀을 다시 읽는다. 기존 스캔과 근거가 유지되고 완료 작업은 재실행되지 않았다.

계획 재부팅은 백업 성공·외부 AWS 복구 접근·Tailscale 복구 경로를 확인하고
접근 차단·작업 정리 후 진행한다. 전체 호스트가 fetch 중 강제 종료되는 경우는
별도 위험이다. 브로커 재시작이 capability를 무효화해도 상류 GitHub 토큰은
자체 만료까지 남을 수 있으므로 연동을 무조건 다시 활성화하지 않는다.

2026-11-09 운영 수정으로 배포·점검 스크립트의 이전 runtime.env 의존성을
제거했다. AWS의 현재 값과 일치하고 실행 중인 앱이 참조하지 않는 runtime.env,
private-broker.env, 조직 App PEM 세 사본만 제거했다. managed_runtime.py와
retire-local-credentials.py가 관리형 비밀 조회·비교·복구를 담당한다. 메타데이터는
operator/retired-local-credentials.json에 비밀 값 없이 보관한다.

필요하면 retire-local-credentials.py --recover-to-ram으로 현재 관리형 값을
/run/aegisai-legacy-recovery에만 복원할 수 있다. 운영 설정을 자동으로 바꾸지
않는다. 실제 RAM 복원과 값 비교 후 임시 파일 정리까지 확인했다. 일반 점검은
verify-runtime-candidate.py가 담당하며 백업 복원 시험을 자동 반복하지 않는다.

과거 runtime.env.before-*와 미사용 OAuth pending 파일 등 다른 사본은 이번
제거 범위 밖이다. 원래 미암호화 EBS 디스크·스냅샷도 사용자 지시대로 보존했다.
모든 과거 비밀 사본을 제거했다고 표현하지 않는다. 비밀 회전 후에는 활성
프로세스 재로딩, 실제 로그인·SCM 접근과 복구 경로를 확인해야 한다.
