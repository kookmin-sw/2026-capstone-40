# 구현

## 구현된 구성 요소

### Packet capture (`src/capture.rs`)

live NIC 또는 offline `.pcap` file에서 traffic을 읽고 TCP flow를 파싱합니다.

- Ethernet → IPv4/IPv6 → TCP 전체 파싱 (VLAN 태그 지원)
- TCP payload length, ACK number, flag 추출
- 모든 raw frame을 Passive DNS cache로 전달
- TCP packet을 prefilter flow table로 전달
- 500ms drain 주기로 분류된 flow를 pipeline에 전달
- IP cooldown 중복 제거, private address filtering

### ARI prefilter (`src/prefilter/`)

encrypted traffic flow를 app class로 분류하는 XGBoost classifier입니다.

**모듈 구조:**

| 파일 | 역할 |
|---|---|
| `flow_table.rs` | 5-tuple key 기반 flow accumulator. SYN 기반 server direction 결정, LRU eviction |
| `features.rs` | ARI feature extraction (Python `core/utils.py` 1:1 port). inverse ACK delta와 edge case까지 맞춤 |
| `model.rs` | XGBoost native JSON parser + tree-walk inference. numerically stable softmax. XGBoost 3.x `base_score` 처리 |
| `labels.rs` | TOML class table. `kind = benign/known/malicious` + `typical_domains` |
| `types.rs` | `FlowKey`, `ParsedPkt`, `FlowState`, `Verdict`, `PrefilterOutput` |
| `mod.rs` | `Prefilter::load()`, `ingest()`, `drain_classified()` |

**검증:** `tests/prefilter_golden.rs` — 33개 feature extraction case와 50개 `predict_proba` case를 Python reference와 비교해 1e-4 오차 이내로 검증합니다.

**설정 (하드코딩 없음):**
```toml
[prefilter]
skip_ports = [22, 23, 25, 53, ...]   # 분류 제외 포트
skip_ips   = ["8.8.8.8", "1.1.1.1"] # 분류 제외 IP
conf_threshold = 0.5                  # Unknown 판정 임계값
```

### Passive DNS (`src/ip_to_domain/passive_dns.rs`)

UDP/53 DNS response를 wire에서 직접 parse해 IP→domain mapping을 실시간으로 구축합니다.

- RFC 1035 wire format parser (compression pointer, A/AAAA record 지원), pure Rust
- capture thread(write) ↔ worker thread(read)가 `Arc<RwLock<HashMap>>` 공유
- TTL 기반 automatic expiration
- `ip_to_domain::lookup()`에서 PTR보다 먼저 조회되는 `passive-dns` source

### IP→domain lookup (`src/ip_to_domain/`)

provider chain을 module 단위로 나누어 구성했습니다.

```
passive-dns → ptr → hackertarget
```

| 모듈 | 역할 |
|---|---|
| `passive_dns.rs` | live DNS sniffing cache |
| `ptr.rs` | OS resolver reverse PTR lookup, SQLite cache |
| `hackertarget.rs` | HackerTarget reverse IP API, 1초 throttling |
| `verify.rs` | Cloudflare DoH forward verification |
| `cache.rs` | SQLite response cache |

### Alert 및 risk scoring

prefilter classification 결과를 즉시 DB alert로 변환합니다.

| Verdict | Severity | Alert type | Risk |
|---|---|---|---|
| Malicious | 4 (high) | PREFILTER_MALICIOUS | +60 |
| Unknown | 2 (low) | PREFILTER_UNKNOWN | +15 |
| Known | 1 (info) | PREFILTER_CLASSIFIED | +0 |
| Benign | — | (drop) | — |

### Web dashboard (`src/web/`)

JavaScript 없는 server-side rendering dashboard입니다. Askama compile-time template을 사용합니다.

**Prefilter panel:**
- 활성화/비활성화 상태 표시
- malicious / unknown / classified flow 비율 bar chart
- DB 크기, queue depth, 마지막 probe 시각

**Alert type label:**
- `PREFILTER_MALICIOUS` → "ARI: malicious"
- `PREFILTER_UNKNOWN` → "ARI: low conf"
- `PREFILTER_CLASSIFIED` → "ARI: classified"

### Training pipeline (`scripts/main.py`)

단일 command로 전체 pipeline을 실행합니다.

```bash
uv run --project scripts python3 scripts/main.py all \
  --target-flows 300 \
  --max-visits 50
```

**단계:**

| Step | 설명 |
|---|---|
| `capture` | Playwright stealth Chromium으로 URL 방문, site별 pcap 저장. target flow 수에 도달할 때까지 자동 반복 |
| `extract` | pcap → ARI format parquet. private IP / DNS resolver IP / non-web port filtering |
| `train` | inverse-frequency sample weight로 class imbalance 보정. XGBoost multi:softprob |
| `export` | `prefilter.json` + `prefilter_labels.toml` → `~/.local/share/capstone/` |

**Adaptive capture:**
- `--target-flows N`: 각 site의 pcap에 N개 TCP flow가 쌓일 때까지 방문 반복
- flow를 많이 생성하는 site는 적게, 적게 생성하는 site는 많이 방문해 class balance를 맞춤

## 계획된 구성 요소

| 구성 요소 | 상태 |
|---|---|
| `passive_filter.rs` — domain heuristic scoring | ⬜ |
| `active_probe.rs` — HTML 수집, screenshot, redirect chain | ⬜ |
| `fingerprint.rs` — SHA-256 hash, content signal | ⬜ |
| `detector.rs` — diff 기반 alert 생성 | ⬜ |
| known_bad / Tranco import | ⬜ |
