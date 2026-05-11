# 트래픽 기반 도메인 위험 모니터

Capstone 2026 Team 40은 암호화된 네트워크 트래픽 속에서 의심스러운 도메인을 찾아내는 Rust 기반 모니터링 파이프라인을 구축했습니다.

시스템은 live packet capture에서 시작합니다. 암호화된 TCP flow를 payload 검사 없이 분류하고, IP를 domain으로 reverse lookup한 뒤, risk score에 따라 고위험 대상만 active probe합니다. 분석 결과는 Rust로 rendering되는 local web dashboard에서 실시간으로 확인할 수 있습니다.

## 핵심 특성

- **Payload를 보지 않는 passive classification** — ARI(ACK-guided Reverse Inference) algorithm으로 TLS 암호화 flow를 분류합니다. packet length와 ACK delta sequence만 사용하며, packet content에는 접근하지 않습니다.
- **Passive DNS cache** — UDP/53 response를 직접 parse해 IP→domain mapping을 실시간으로 구축합니다. PTR reverse lookup보다 빠르고, ECH/ESNI 환경에서도 사용할 수 있습니다.
- **2단계 filtering** — prefilter(≤100µs/flow, metadata only)가 먼저 대상을 선별하고, Chromium 기반 active probe(~5–10초)는 고위험 대상에만 실행합니다.
- **구성 가능한 training pipeline** — 한 명령으로 capture → extract → train → export 과정을 실행합니다.

## 주요 기능

| 기능 | 설명 |
|---|---|
| Traffic capture | live NIC와 `.pcap` file 지원, Ethernet→IP→TCP 전체 parsing |
| ARI prefilter | 암호화 flow의 app class 분류 (Benign / Known / Unknown / Malicious) |
| Passive DNS | UDP/53 sniffing으로 실시간 IP→도메인 cache 구축 |
| IP→domain lookup | Passive DNS → PTR → HackerTarget 순서로 시도 |
| 위험도 score | prefilter signal(+15/+60)과 domain heuristic signal 결합 |
| Active probe | 고위험 도메인의 HTML, redirect, screenshot, metadata 수집 |
| Alert system | severity별 alert (`PREFILTER_MALICIOUS` sev-4, `PREFILTER_UNKNOWN` sev-2) |
| Web dashboard | prefilter panel, alert, domain list, traffic chart |

## 화면 구성

| 화면 | 제공 정보 |
|---|---|
| Dashboard | 활성 alert, 추적 중인 domain, capture IP, prefilter 분류 현황 (malicious/unknown/classified) |
| 알림 | 심각도, ARI 분류 유형, 도메인, confidence, timestamp |
| Domain list | risk score, decision, IP, last seen time, alert 수 |
| 도메인 상세 | IP 이력, alert, 위험 signal |
| Probe | source 선택과 검증을 포함한 reverse IP lookup |

## 필요성

ECH(Encrypted Client Hello)가 확산되면서 SNI 기반 트래픽 분류는 점점 실효성을 잃고 있습니다. 이 프로젝트는 패킷 metadata(길이, ACK sequence)만으로 암호화 트래픽을 분류하는 ARI 방식을 적용해, 더 강하게 암호화된 환경에서도 동작할 수 있는 passive monitoring pipeline을 구성합니다.
