# Usage

The project runs as a local Rust application with a small web dashboard.

## Install

Requirements:

- Rust toolchain with Cargo.
- SQLite support through `rusqlite`.
- Optional packet capture input from a live interface or `.pcap` file.

Install dependencies and build:

```bash
cargo build
```

## Run

Start the application:

```bash
cargo run -- serve
```

The example configuration in the source repository binds to:

```text
0.0.0.0:8080
```

## Configure

The application loads `capstone.toml` from the current directory first, then checks:

```text
~/.config/capstone/capstone.toml
```

Important configuration areas:

- `store`: database path and snapshot directory.
- `capture`: live interface, `.pcap` file, IP cooldown, and private-address filtering.
- `probe`: timeout, maximum assets, screenshot behavior, and Chromium path.
- `filter`: watch and probe thresholds.
- `api`: bind address and worker count.
- `ip_to_domain`: lookup sources, cache path, and verification behavior.

## CLI Shape

The source plan defines these subcommands:

- `serve`: start the API and frontend server.
- `capture`: capture packets from a live NIC or `.pcap` file.
- `probe`: actively probe a single domain.
- `import-bad`: import a known-bad indicator list.
- `score`: run passive risk scoring on a domain.

## Dashboard Routes

- `/dashboard`: overview metrics and pipeline status.
- `/alerts`: active alert review.
- `/domains`: domain inventory.
- `/domains/<domain>`: domain detail and history.
- `/probe`: reverse IP lookup tool.
