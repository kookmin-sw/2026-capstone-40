"""Manifest-based storage helpers.

Each domain gets a `manifest.json` inside its output folder that tracks every
scrape run and its metadata.  Old snapshots can be pruned automatically when
`max_snapshots` is set.
"""

import json
import shutil
from pathlib import Path


MANIFEST_FILE = "manifest.json"


def load_manifest(domain_dir: Path) -> dict:
    manifest_path = domain_dir / MANIFEST_FILE
    if manifest_path.exists():
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    return {"domain": domain_dir.name, "runs": []}


def save_manifest(domain_dir: Path, manifest: dict) -> None:
    manifest_path = domain_dir / MANIFEST_FILE
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def record_run(output_dir: Path, result: dict, max_snapshots: int = 0) -> None:
    """Append a scrape result to the domain manifest and prune old snapshots."""
    domain_slug = result["domain"].replace(".", "_")
    domain_dir = output_dir / domain_slug
    domain_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_manifest(domain_dir)
    manifest["domain"] = result["domain"]
    manifest["runs"].append(result)

    if max_snapshots > 0 and len(manifest["runs"]) > max_snapshots:
        # Remove oldest snapshots beyond the limit
        runs_to_remove = manifest["runs"][: len(manifest["runs"]) - max_snapshots]
        for old_run in runs_to_remove:
            snapshot_path = Path(old_run.get("snapshot_dir", ""))
            if snapshot_path.exists() and snapshot_path.is_dir():
                shutil.rmtree(snapshot_path)
        manifest["runs"] = manifest["runs"][-max_snapshots:]

    save_manifest(domain_dir, manifest)


def load_global_index(output_dir: Path) -> dict:
    """Load the top-level index that points to every tracked domain."""
    index_path = output_dir / "index.json"
    if index_path.exists():
        return json.loads(index_path.read_text(encoding="utf-8"))
    return {"domains": []}


def save_global_index(output_dir: Path, domains: list[str]) -> None:
    index_path = output_dir / "index.json"
    index_path.write_text(
        json.dumps({"domains": sorted(set(domains))}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
