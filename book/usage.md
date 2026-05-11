# 사용법

로컬 Rust application으로 실행되며, web dashboard를 내장합니다.

## 요구 사항

- Rust toolchain (Cargo 포함)
- tcpdump (`cap_net_raw,cap_net_admin` 권한 필요, 또는 sudo)
- training pipeline: Python 3.10+, [uv](https://github.com/astral-sh/uv), Playwright Chromium

## 빌드 및 실행

```bash
cargo build --release

# live capture 및 dashboard server 시작 (root 또는 CAP_NET_RAW 필요)
sudo ./target/release/capstone serve
```

기본 dashboard 주소: `http://0.0.0.0:8080`

## 설정 (`capstone.toml`)

| 섹션 | 주요 설정 항목 |
|---|---|
| `store` | DB path, snapshot directory |
| `capture` | interface 또는 `.pcap` file, IP cooldown, private address filtering |
| `prefilter` | model/label path, `skip_ports`, `skip_ips`, `conf_threshold` |
| `probe` | timeout, 최대 asset 수, Chromium 경로 |
| `filter` | `watch` / `probe` 임계값 |
| `ip_to_domain` | lookup source 순서, cache path, DoH verification |
| `api` | bind address, worker 수 |

### Prefilter 설정 예시

```toml
[prefilter]
enabled        = true
model_path     = "~/.local/share/capstone/prefilter.json"
labels_path    = "~/.local/share/capstone/prefilter_labels.toml"
length_dim     = 10
conf_threshold = 0.5

# 분류 제외 port (training data에 없는 traffic)
skip_ports = [22, 23, 25, 53, 110, 123, 143, 389, 3478, 5353]

# 분류 제외 IP (DNS-over-HTTPS resolver)
skip_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
```

## Training pipeline

전체 pipeline을 한 command로 실행합니다.

```bash
# 필요한 package 설치 (최초 1회)
uv run --project scripts python3 -m playwright install chromium

# 전체 pipeline 실행
uv run --project scripts python3 scripts/main.py all \
  --target-flows 300 \
  --max-visits 50

# 또는 step별 실행
uv run --project scripts python3 scripts/main.py capture --target-flows 300
uv run --project scripts python3 scripts/main.py extract
uv run --project scripts python3 scripts/main.py train
uv run --project scripts python3 scripts/main.py export
```

**주요 옵션:**

| Option | 기본값 | 설명 |
|---|---|---|
| `--target-flows N` | 50 | site별 target TCP flow 수 (초과 시 다음 site로) |
| `--max-visits N` | 30 | site별 최대 visit 횟수 (safety limit) |
| `--dwell N` | 20 | page당 dwell time(초) |
| `--iface NAME` | enp7s0 | capture interface |
| `--page-list PATH` | utils/webscrapper/page_list.txt | URL list file |

training이 끝나면 model은 `~/.local/share/capstone/prefilter.json`과 `prefilter_labels.toml`에 저장됩니다. `capstone serve`를 재시작하면 바로 적용됩니다.

## Dashboard routes

| 경로 | 내용 |
|---|---|
| `/` | overview — active alert, tracked domain, capture IP, prefilter 현황 |
| `/alerts` | alert list (ARI classification type 포함) |
| `/domains` | domain list (risk score, decision) |
| `/domains/<domain>` | domain detail 및 history |
| `/probe` | reverse IP lookup tool |

## tcpdump 권한 설정

```bash
# non-root 실행을 위한 권한 부여 (1회)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
```
