# Implementation

The completed system is organized as a local monitoring pipeline with a Rust-rendered investigation interface.

## Capture and Store

The capture layer reads live traffic or offline `.pcap` input, normalizes useful observations, and writes durable state to SQLite.

Implemented behavior:

- Configurable capture source.
- IP cooldown and private-address filtering.
- Stored domain and IP observations.
- Dashboard-visible pipeline status.

## Active Probe and Snapshot

Targets that cross the configured risk threshold are probed so the analyst can review domain evidence instead of raw traffic alone.

Implemented behavior:

- HTML fetch and HTTP metadata capture.
- Redirect chain recording.
- Screenshot support through headless Chromium when configured.
- Asset and favicon collection for fingerprinting.
- Snapshot storage.
- Domain detail evidence history.

## Filter and Score

The filter classifies observed domains into `skip`, `watch`, or `probe` decisions using visible thresholds and risk classes.

Implemented behavior:

- Signal rows on domain detail pages.
- Configurable `watch` and `probe` thresholds: below `30` skips, `30` to `60` watches, above `60` probes.
- Clear risk classes for low, medium, and high risk.
- Alert generation for high-priority findings.

Scoring inputs include known-bad indicators, suspicious TLDs, entropy, typosquatting distance, homograph signals, fast-flux behavior, and newly observed domains.

## Dashboard and Review

The dashboard gives the reviewer a compact operational view and links summary metrics to domain and alert detail.

Implemented behavior:

- Active alert review.
- Domain inventory.
- Severity breakdown.
- Probe history.
- Acknowledgment workflow.
