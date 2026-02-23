# Net Finder

로컬 네트워크의 호스트를 실시간으로 탐색하고 모니터링하는 웹 대시보드입니다. 네트워크 인프라 탐지와 보안 위협 감시까지 단일 정적 바이너리로 수행합니다.

## 기능

- **ARP 기반 호스트 탐색** — ARP 요청을 통해 서브넷을 스캔하고, 수동 ARP 트래픽 캡처로 활성 호스트를 발견합니다
- **IP 충돌 감지** — 같은 IP를 사용하는 여러 MAC 주소를 식별하며, NIC 본딩/티밍과 실제 충돌을 구분합니다
- **DHCP 서버 탐지** — 네트워크의 DHCP 서버를 발견하고 제공 IP, 서브넷 마스크, 라우터, DNS 서버 정보를 표시합니다
- **호스트명 해석** — DNS PTR, NetBIOS, mDNS, SNMP sysName, TLS 인증서, SMTP 배너를 통해 호스트명을 해석합니다
- **OUI 벤더 조회** — IEEE OUI 데이터베이스를 사용하여 MAC 주소를 하드웨어 벤더에 매핑합니다
- **네트워크 프로토콜 리스너**
  - **HSRP** (Hot Standby Router Protocol) — Cisco HSRP v1/v2 광고 감지
  - **VRRP** (Virtual Router Redundancy Protocol) — VRRP 광고 캡처
  - **LLDP** (Link Layer Discovery Protocol) — 인접 스위치 및 네트워크 장비 탐색
  - **CDP** (Cisco Discovery Protocol) — Cisco 장비 및 상세 정보 탐색
- **보안 모니터링**
  - **ARP 스푸핑 탐지** — 기준선 대비 ARP 트래픽을 지속 감시하며, 게이트웨이 스푸핑 시 긴급 알림 발생
  - **DNS 스푸핑 탐지** — 여러 DNS 서버의 응답을 비교하여 불일치 및 비정상적으로 빠른 응답을 감지
- **웹 대시보드** — 실시간 스캔 진행률, 호스트 목록, 충돌 알림, 프로토콜 정보를 표시하는 싱글 페이지 웹 UI

## 요구 사항

- Linux
- Go 1.21 이상
- root 권한 (원시 패킷 캡처에 필요)

외부 C 라이브러리가 필요 없습니다. Linux AF_PACKET raw socket을 직접 사용하여 런타임 의존성 없는 완전 정적 바이너리를 생성합니다.

## 빌드

```bash
make build
```

CGo를 비활성화한 명시적 정적 빌드:

```bash
CGO_ENABLED=0 make build
```

기타 타겟:

```bash
make clean       # 바이너리 삭제
make deps        # Go 모듈 다운로드 및 정리
make fmt         # 소스 코드 포맷팅
make vet         # go vet 실행
```

## 설치

```bash
sudo make install    # /usr/local/bin에 설치
sudo make uninstall  # /usr/local/bin에서 제거
```

## 사용법

```bash
sudo ./net-finder [옵션]
```

### 옵션

| 플래그 | 기본값 | 설명 |
|--------|--------|------|
| `-i` | (자동 감지) | 사용할 네트워크 인터페이스 |
| `-s` | (자동 탐색) | 스캔할 서브넷 (콤마 구분 CIDR, 예: `192.168.1.0/24,10.0.0.0/24`) |
| `-p` | `9090` | 웹 대시보드 포트 |
| `-auto` | `true` | 실행 시 자동 스캔 시작 |

### 예시

```bash
# 인터페이스와 서브넷 자동 감지, 포트 9090에서 대시보드 실행
sudo ./net-finder

# 인터페이스와 서브넷 지정
sudo ./net-finder -i eth0 -s 192.168.1.0/24

# 여러 서브넷을 커스텀 포트로 스캔
sudo ./net-finder -s 192.168.1.0/24,10.0.0.0/24 -p 8080

# 자동 스캔 없이 시작 (웹 UI에서 수동 트리거)
sudo ./net-finder -auto=false
```

웹 대시보드는 `http://localhost:9090` (또는 지정한 포트)에서 자동으로 열립니다.

## 동작 방식

1. **OUI 데이터베이스 로드** — IEEE OUI 벤더 데이터베이스를 다운로드하고 캐싱합니다
2. **병렬 스캔** — 모든 탐색 단계를 동시에 실행합니다:
   - 대상 서브넷 전체에 ARP 스캔 후 호스트명 해석
   - DHCP 서버 탐지 후 DNS 스푸핑 검사
   - HSRP, VRRP, LLDP, CDP 프로토콜 리스너 (30초 캡처 윈도우)
3. **백그라운드 모니터링** — 초기 스캔 완료 후 지속적으로 감시합니다:
   - 새로운 HSRP/VRRP/LLDP/CDP 광고
   - 스푸핑 가능성을 나타내는 ARP 트래픽 이상

패킷 캡처는 Linux `AF_PACKET` raw socket과 커널 수준 BPF 필터를 사용하여 libpcap 없이 동작합니다. 패킷 파싱은 `gopacket/layers` (순수 Go)로 처리합니다.

## API 엔드포인트

| 엔드포인트 | 메서드 | 설명 |
|------------|--------|------|
| `/api/status` | GET | 스캔 상태 및 진행률 |
| `/api/scan/start` | POST | 새 스캔 시작 |
| `/api/scan/stop` | POST | 현재 스캔 중지 |
| `/api/hosts` | GET | 발견된 호스트 목록 |
| `/api/conflicts` | GET | IP 주소 충돌 |
| `/api/dhcp` | GET | 탐지된 DHCP 서버 |
| `/api/hsrp` | GET | HSRP 광고 |
| `/api/vrrp` | GET | VRRP 광고 |
| `/api/lldp` | GET | LLDP 이웃 장비 |
| `/api/cdp` | GET | CDP 이웃 장비 |
| `/api/hostnames` | GET | 해석된 호스트명 |
| `/api/security/arp` | GET | ARP 스푸핑 알림 |
| `/api/security/dns` | GET | DNS 스푸핑 알림 |
| `/api/interfaces` | GET | 사용 가능한 네트워크 인터페이스 |

## 라이선스

이 프로젝트는 MIT 라이선스로 배포됩니다. 자세한 내용은 [LICENSE](../LICENSE)를 참조하세요.
