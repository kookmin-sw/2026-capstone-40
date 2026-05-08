# Architecture

The project is organized around a local monitoring pipeline and a server-rendered Rust interface.

## Runtime Components

| Component | Responsibility |
| --- | --- |
| Capture | Reads live traffic or offline packet captures and extracts network observations. |
| IP-to-domain lookup | Maps observed IP addresses to candidate domains using PTR and external lookup sources. |
| Filter | Classifies targets into `skip`, `watch`, or `probe` using configurable thresholds. |
| Probe | Fetches and records metadata for targets that deserve deeper inspection. |
| Store | Persists domain history, alerts, pipeline status, and probe state in SQLite. |
| Frontend | Renders the dashboard, alerts, domains, domain detail, charts, and probe pages. |

## Rust Stack

- `tiny_http` provides the local HTTP server.
- `askama` renders HTML templates.
- `rusqlite` stores dashboard and pipeline state.
- `serde`, `serde_json`, and `toml` handle configuration and structured data.
- `ureq` supports HTTP calls for probing and lookup utilities.

## Data Flow

1. Capture observes network traffic from an interface or `.pcap`.
2. Observed IP addresses enter the lookup and filtering stages.
3. Reverse lookup sources produce candidate domains.
4. Risk scoring assigns a decision: `skip`, `watch`, or `probe`.
5. Probe work records metadata and snapshot evidence.
6. The dashboard exposes recent domains, alerts, severity counts, and pipeline status.

## Delivered Interface

- Dashboard: current totals, alert severity breakdown, recent alerts, recent domains, and pipeline status.
- Alerts: severity, type, domain, detail, timestamp, and acknowledgment state.
- Domains: risk score, decision, IP list, last seen time, and alert count.
- Domain detail: IP history, risk class, alert history, signals, and snapshots.
- Probe: reverse IP lookup with source selection and optional verification.
