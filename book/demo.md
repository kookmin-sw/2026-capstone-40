# 데모

traffic capture부터 ARI prefilter classification, domain risk 평가까지 이어지는 전체 흐름을 보여줍니다.

## 시연 시나리오

### 1. Training pipeline

```bash
# 대상 URL 목록으로 traffic capture → train → model export
uv run --project scripts python3 scripts/main.py all \
  --target-flows 300 --max-visits 50
```

- Playwright stealth Chromium이 각 URL을 방문하며 pcap 수집
- site별 target flow 수에 도달할 때까지 자동 반복 방문
- inverse-frequency sample weight로 class imbalance 자동 보정
- 학습된 XGBoost model을 native JSON으로 export해 Rust runtime에 적용

### 2. Live monitoring

```bash
sudo ./target/release/capstone serve
```

dashboard에서 확인할 수 있는 항목:

- **Prefilter panel**: 분류된 flow 수 (malicious / unknown / classified 비율)
- **Alerts**: ARI classification type ("ARI: malicious", "ARI: low conf")과 confidence
- **Domain list**: prefilter signal로 상승한 risk score

### 3. Traffic generation (demo용)

```bash
cd utils/traffic_capture
uv run python3 gen_traffic.py --loops 3 --dwell 15
```

`page_list.txt`의 URL을 반복 방문해 prefilter가 분류할 traffic을 생성합니다.
