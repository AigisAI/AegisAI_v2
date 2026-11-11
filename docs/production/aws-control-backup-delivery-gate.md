# 단일 EC2 제어 영역 복구와 배포 인증

기존 서울 리전의 비공개 EC2와 S3 버킷을 사용한다. 오프호스트 복구와 GitHub 배포 인증은 AWS 운영자 권한으로 한 번 설정한다. 앱의 EC2 역할 권한은 기존과 동일하다.

## 제어 영역 백업

1. 로컬 제어 영역 백업이 정상인지 확인한다. 백업은 SQLite, K3s 토큰, 암호화 설정, 트래픽 상태 파일을 포함한다.
2. 검토한 리비전의 `offsite_control_backup.py`와 `control_recovery.py`를 함께 root 전용 디렉터리에 설치한다. 승인된 운영자 프로필과 기존 AWS CLI가 필요하다.
3. root에서 `python3 -B offsite_control_backup.py /opt/aegisai/kubernetes/control-backups/<snapshot>`을 실행한다. 백업 위치는 기존 S3 버킷의 `infrastructure-state/340/control/`이다.
4. S3 비공개 상태와 지정 KMS 키 암호화, EC2 앱 역할의 객체 조회 거부, 다운로드 해시 일치, 격리된 K3s API 기동과 백업 데이터 조회를 확인한다. 완료 근거는 `/opt/aegisai/kubernetes/offsite-control-recovery-result.json`에 기록된다.

## GitHub Actions OIDC

1. 대상 AWS 계정과 기존 GitHub OIDC 공급자 유무를 확인한다. 기존 공급자가 있으면 별도 생성 대신 현재 구성을 확인하고 가져오기 여부를 결정한다.
2. `deploy/aws-ec2/platform/oidc`의 별도 상태에서 계획을 확인한다. 정책은 지정 저장소의 검증 브랜치만 허용하며, 기존 S3 버킷의 위치·암호화·공개 상태를 읽는다.
3. 검토한 계획을 적용하고 GitHub 변수 `AEGISAI_DELIVERY_OIDC_ENABLED`를 활성화한다. 검증 워크플로에서 AWS 역할 전환과 S3 보안 설정 읽기 성공, 객체 목록 읽기 거부를 확인한다.
4. 같은 브랜치에서 운영 릴리스 값을 커밋한다. root 전용 승격 도구는 동일한 Git 커밋의 고정 워크플로 내용과 AWS 검증 성공을 확인한 뒤 이미지 서명과 상태를 검증한다.

## 2026-11-11 운영 근거

- 기존 버킷에 새 제어 영역 백업 1개를 저장했다. 다운로드 SHA-256과 명시한 KMS 키가 일치했고, 앱의 EC2 역할로 백업 조회는 거부됐다. 내려받은 파일로 격리된 K3s API를 7.548초에 기동해 Git 리비전, 승인 이미지 참조, 암호화된 Secret과 비활성 프로필 두 개를 확인했다. 운영 Pod와 Docker 컨테이너는 그대로 유지됐다.
- 별도 Terraform 상태로 GitHub OIDC 공급자·CI 역할·읽기 정책 3개를 추가했다. 기존 AWS 자원 수정 및 삭제는 0건이었다. GitHub Actions 실행 42979294896에서 실제 역할 전환, 지정 버킷의 보안 설정 조회, 객체 목록 조회 거부를 확인했다.
- Windows의 기존 운영자 인증 도구가 다시 연결됐고, 로그인할 때 시작하는 자동 갱신 작업을 재등록했다. 이 방식은 해당 Windows 계정 세션과 네트워크 연결이 필요하다.
- 이 복구는 별도 디렉터리와 로컬 포트에서 실행한 제어 영역 복구다. 전체 EC2 재구성과 AWS 게이트를 통과한 새 운영 릴리스의 실제 전환 검증은 별도로 남아 있다.


## 서울 리전 운영 비용 기준

2026-11-11에 실행 중인 Linux m7i-flex.large 1대, 퍼블릭 IPv4 1개, 암호화된 gp3 50 GiB를 확인했다. 공인 IP는 Tailscale의 네트워크 연결에 사용하며 서비스 인바운드는 비공개로 제한한다. EC2와 gp3 정가는 서울 리전 SKU를 AWS Price List Query API에서 조회했다. [AWS Price List Query API](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/using-price-list-query-api.html)

| 항목 | 산식 | 월 정가 |
| --- | --- | ---: |
| EC2 | 730시간 × $0.11771 | $85.93 |
| gp3 | 50 GiB × $0.0912 | $4.56 |
| IPv4 | 730시간 × $0.005 | $3.65 |
| Secrets Manager | 2개 × $0.40 | $0.80 |
| 애플리케이션 KMS 키 | 1개 × $1.00 | $1.00 |
| 합계 | 할인·세금 적용 전 추정 | **$95.94** |

보존한 이전 볼륨과 스냅샷, S3 저장·요청, KMS·Secrets Manager 요청, 데이터 전송은 사용량에 따라 추가된다. 운영자 계정은 AWS 비용 태그 조회를 거부받아 프로젝트별 실청구액은 확인하지 못했다. [EBS 요금](https://aws.amazon.com/ebs/pricing/) · [IPv4 요금](https://aws.amazon.com/vpc/pricing/) · [Secrets Manager 요금](https://aws.amazon.com/secrets-manager/pricing/) · [KMS 요금](https://aws.amazon.com/kms/pricing/)
