# 사용법

이 프로젝트는 작은 웹 대시보드를 포함한 로컬 Rust 애플리케이션으로 실행됩니다.

## 설치

요구 사항:

- Cargo를 포함한 Rust toolchain.
- `rusqlite`를 통한 SQLite 지원.
- 선택 사항: 실시간 인터페이스 또는 `.pcap` 파일 기반 패킷 캡처 입력.

의존성을 설치하고 빌드합니다:

```bash
cargo build
```

## 실행

애플리케이션을 시작합니다:

```bash
cargo run -- serve
```

소스 저장소의 예시 설정은 다음 주소에 바인딩합니다:

```text
0.0.0.0:8080
```

## 설정

애플리케이션은 먼저 현재 디렉터리의 `capstone.toml`을 읽고, 없으면 다음 위치를 확인합니다:

```text
~/.config/capstone/capstone.toml
```

주요 설정 영역:

- `store`: 데이터베이스 경로와 스냅샷 디렉터리.
- `capture`: 실시간 인터페이스, `.pcap` 파일, IP 재처리 대기 시간, 사설 주소 필터링.
- `probe`: timeout, 최대 asset 수, 스크린샷 동작, Chromium 경로.
- `filter`: watch 및 probe 임계값.
- `api`: bind 주소와 worker 수.
- `ip_to_domain`: 조회 소스, 캐시 경로, 검증 동작.

## CLI 형태

소스 계획은 다음 하위 명령을 정의합니다:

- `serve`: API 및 frontend 서버를 시작합니다.
- `capture`: 실시간 NIC 또는 `.pcap` 파일에서 패킷을 캡처합니다.
- `probe`: 단일 도메인을 능동적으로 프로브합니다.
- `import-bad`: known-bad 지표 목록을 가져옵니다.
- `score`: 도메인에 대해 수동 위험도 점수를 계산합니다.

## 대시보드 라우트

- `/dashboard`: 개요 지표와 파이프라인 상태.
- `/alerts`: 활성 알림 검토.
- `/domains`: 도메인 목록.
- `/domains/<domain>`: 도메인 상세 및 이력.
- `/probe`: 역방향 IP 조회 도구.
