# 아키텍처

이 시스템은 local monitoring pipeline과 server-side rendering 방식의 Rust interface를 중심으로 구성됩니다.

## 전체 파이프라인

```
[라이브 NIC / .pcap]
        │
        ▼
  packet_capture
        │
        ├──→ passive_dns.ingest_frame()    ← UDP/53 packet parsing, IP→domain cache 구축
        │
        ▼ (TCP만)
  prefilter (ARI)
        │  5-tuple 단위 flow 누적 → ARI feature 추출 → XGBoost 분류
        │
        ├─ Benign (high confidence) → drop (benign_skip 설정 시)
        ├─ Known (high confidence)  → alert sev-1 + risk +0
        ├─ Unknown (low confidence) → alert sev-2 + risk +15
        └─ Malicious                → alert sev-4 + risk +60
        │
        ▼
  ip_to_domain lookup
        │  Passive DNS cache → PTR → HackerTarget 순서
        │
        ▼
  passive_filter           ← 계획됨
        │  domain heuristic signal + prefilter signal → risk score
        │  SKIP / WATCH / PROBE decision
        │
        ▼ (PROBE만)
  active_probe             ← 계획됨
  fingerprint / detector   ← 계획됨
        │
        ▼
  SQLite store ←→ web dashboard (Askama SSR)
```

## Runtime thread 구조

| Thread | 역할 |
|---|---|
| capture thread | pcap loop, packet parsing, prefilter ingest, Passive DNS ingest |
| N worker threads | IP→domain lookup, domain risk 평가, DB 기록 |
| API thread | tiny_http loop, SSR page 제공 |

capture thread와 worker thread는 `PassiveDnsCache` (`Arc<RwLock<HashMap>>`)를 공유합니다. capture thread가 쓰고, worker thread는 lookup 과정에서 읽습니다.

## Prefilter (ARI) 상세

ARI는 encrypted traffic classification algorithm입니다. reference implementation은 `utils/ARI-ACK-guided-Reverse-Inference-main/`에 있습니다.

**Feature extraction (Python `core/utils.py::feature_extraction_ari` 1:1 port):**

1. flow에서 `select_dir` 방향(기본: server→client) packet만 추출
2. 첫 `dim`개 packet의 payload length → length subvector
3. 같은 packet들의 TCP ACK number delta 계산: `Δᵢ = -(ACKᵢ - ACKᵢ₋₁)` (양수이고 ≤ 100,000인 경우)
4. 두 값을 이어 붙여 `[length dim개 | ACK delta dim개]` 크기의 `2×dim` feature vector 생성

**XGBoost runtime (pure Rust):**
- Python에서 학습한 뒤 `model.save_model("prefilter.json")`으로 export
- Rust에서 native JSON parsing + tree walk로 직접 inference
- C library dependency 없이 `serde_json` 재사용
- XGBoost 3.x의 class별 `base_score` string vector format 처리

**Flow accumulation:**
- 5-tuple key로 `FlowTable`에서 packet buffering
- SYN을 관찰하면 server 방향을 결정하고, 관찰하지 못한 경우 low-port heuristic 사용
- `select_dir` 방향으로 `dim`개 packet이 쌓이면 분류 후 drain
- LRU eviction (`max_flows`), timeout eviction (`flow_timeout_s`)

## Passive DNS 상세

ECH(Encrypted Client Hello) 도입으로 SNI 추출이 불가능해지는 환경에 대응합니다.

- capture thread가 모든 raw frame을 `PassiveDnsCache::ingest_frame()`에 전달
- UDP port 53 response에서 RFC 1035 wire format parsing (compression pointer 지원)
- A/AAAA record에서 (IP, domain, TTL) 추출
- TTL 기반 expiration (30초~3600초 clamp)
- `ip_to_domain::lookup()`에서 PTR보다 먼저 lookup

## Rust stack

| Crate | 용도 |
|---|---|
| `tiny_http` | 로컬 HTTP 서버 |
| `askama` | compile-time HTML template (SSR, JS 없음) |
| `rusqlite` | SQLite state store (WAL mode) |
| `serde` / `serde_json` / `toml` | config, XGBoost JSON, structured data |
| `ureq` | HTTP lookup + probe |
| `pcap` | live NIC + PCAP file |
| `dns-lookup` | PTR reverse DNS |
| `log` | logging |

총 9개 crate를 사용합니다. XGBoost runtime은 별도 crate 없이 `serde_json`을 재사용합니다.

## Training pipeline

```
scripts/main.py all --target-flows 300 --max-visits 50
  │
  ├─ capture  Playwright stealth browser (DoH 비활성화)
  │           URL별 target flow 수에 도달할 때까지 자동 반복 방문
  │           site별 별도 pcap file (label = site domain)
  │
  ├─ extract  private IP / CGNAT / DNS resolver IP filtering
  │           SPLT-Data, Direction-Data, Ack-Data, Label(integer) column 생성
  │
  ├─ train    inverse-frequency sample weight로 class imbalance 보정
  │           XGBoost multi:softprob, 100 trees, max_depth 10
  │
  └─ export   prefilter.json (native JSON) + prefilter_labels.toml
              → ~/.local/share/capstone/
```
