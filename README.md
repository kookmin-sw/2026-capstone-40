# Capstone 40

암호화된 트래픽의 메타데이터를 이용해 의심스러운 웹 도메인을 탐지하는
네트워크 모니터링 프로토타입입니다. Rust 서비스가 패킷을 수집하고,
ARI/XGBoost 기반 prefilter로 TCP 흐름을 분류한 뒤, IP를 도메인 후보로
변환하여 SQLite에 경고를 저장하고 웹 대시보드로 보여줍니다.

## 프로젝트 소개

이 프로젝트는 payload를 직접 검사하지 않고 패킷 길이와 ACK delta 특징을
사용해 트래픽 흐름을 분석합니다. 이후 DNS/PTR 조회와 HTML fingerprint 비교를
통해 도메인 위험도를 보강합니다.

주요 구성:

- `src/capture.rs` - 패킷 캡처 및 파싱
- `src/prefilter/` - ARI 특징 추출 및 XGBoost JSON 추론
- `src/resolver/` - passive DNS, PTR, HackerTarget, 캐시 조회
- `src/alert/` - 경고 생성 및 위험도 업데이트
- `src/web/`, `templates/` - 웹 대시보드와 경고 페이지
- `scripts/` - 데이터 추출, 학습, 모델 export 파이프라인

## 소개 영상

소개 영상 링크: TBD

## 팀 소개

Capstone Team 40

최종 제출 전 팀원 정보, 담당 역할, 사진 또는 SNS 링크를 추가할 예정입니다.

## 사용법

필요 환경:

- Rust toolchain 및 Cargo
- 패킷 캡처를 위한 libpcap 개발 패키지
- 학습 스크립트 실행을 위한 Python 및 `uv`

빌드 및 테스트:

```bash
cargo build
cargo test
```

대시보드 및 캡처 파이프라인 실행:

```bash
cargo run -- serve 127.0.0.1:8080
```

서비스는 먼저 저장소 루트의 `capstone.toml`을 읽고, 없으면
`~/.config/capstone/capstone.toml`을 사용합니다. 실시간 캡처는
`[capture] interface`, 오프라인 분석은 `pcap_file`을 설정합니다.

IP를 도메인 후보로 변환:

```bash
cargo run -- ip-to-domain 8.8.8.8 --json
```

ARI prefilter 모델 학습 및 export:

```bash
uv run python3 scripts/main.py all
```

자세한 구현 내용은 `plan.md`, `status.md`, `prefilter.md`를 참고하세요.

## 기타

- 실시간 패킷 캡처는 root 권한 또는 `CAP_NET_RAW`가 필요할 수 있습니다.
- 기본 데이터베이스 경로는 `~/.local/share/capstone/capstone.db`입니다.
- reverse-DNS 캐시는 설정된 DNS 캐시 경로에 저장됩니다.
- 일부 CLI subcommand는 아직 placeholder이며, 현재 주요 실행 명령은
  `serve`와 `ip-to-domain`입니다.
