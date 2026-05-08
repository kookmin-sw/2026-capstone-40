# 사용법

로컬 Rust 애플리케이션으로 실행되며, 웹 대시보드를 내장합니다.

## 설치

요구 사항:

- Cargo를 포함한 Rust toolchain
- SQLite (`rusqlite` 크레이트가 정적 링크 또는 시스템 라이브러리 사용)
- 선택 사항: 실시간 인터페이스 또는 `.pcap` 파일 기반 패킷 캡처 입력

빌드:

```bash
cargo build --release
```

## 실행

```bash
cargo run -- serve
```

기본 바인딩 주소:

```text
0.0.0.0:8080
```

## 설정

애플리케이션은 현재 디렉터리의 `capstone.toml`을 먼저 읽고, 없으면 다음 위치를 확인합니다:

```text
~/.config/capstone/capstone.toml
```

| 섹션 | 설정 항목 |
| --- | --- |
| `store` | 데이터베이스 경로, 스냅샷 디렉터리 |
| `capture` | 실시간 인터페이스, `.pcap` 파일, IP 재처리 대기 시간, 사설 주소 필터링 |
| `probe` | timeout, 최대 asset 수, 스크린샷 동작, Chromium 경로 |
| `filter` | `watch` 및 `probe` 임계값 |
| `api` | bind 주소, worker 수 |
| `ip_to_domain` | 조회 소스, 캐시 경로, 검증 동작 |

## CLI 하위 명령

| 명령 | 동작 |
| --- | --- |
| `serve` | API 및 frontend 서버 시작 |
| `capture` | 실시간 NIC 또는 `.pcap`에서 패킷 캡처 |
| `probe` | 단일 도메인 능동 프로브 |
| `import-bad` | known-bad 지표 목록 가져오기 |
| `score` | 도메인에 대해 수동 위험도 점수 계산 |

## 대시보드 라우트

| 경로 | 내용 |
| --- | --- |
| `/dashboard` | 개요 지표와 파이프라인 상태 |
| `/alerts` | 활성 알림 검토 |
| `/domains` | 도메인 목록 |
| `/domains/<domain>` | 도메인 상세 및 이력 |
| `/probe` | 역방향 IP 조회 도구 |

## API 사용

`serve` 명령은 HTML 프론트엔드와 JSON API를 동일한 포트에서 제공합니다. 외부 스크립트나 도구에서 직접 데이터를 가져올 수 있습니다.

기본 base URL:

```text
http://localhost:8080/api
```

예시 요청:

```bash
# 도메인 목록 조회
curl http://localhost:8080/api/domains

# 특정 도메인 상세 조회
curl http://localhost:8080/api/domains/example.com

# 활성 알림 조회
curl http://localhost:8080/api/alerts

# 알림 확인 처리
curl -X POST http://localhost:8080/api/alerts/<id>/ack
```

| 엔드포인트 | 메서드 | 동작 |
| --- | --- | --- |
| `/api/domains` | GET | 도메인 목록 (위험도 점수, 결정 포함) |
| `/api/domains/<domain>` | GET | 도메인 상세, IP 이력, 알림, 신호 |
| `/api/alerts` | GET | 활성 알림 목록 |
| `/api/alerts/<id>/ack` | POST | 알림 확인 처리 |
| `/api/probe` | POST | 역방향 IP 조회 트리거 |
