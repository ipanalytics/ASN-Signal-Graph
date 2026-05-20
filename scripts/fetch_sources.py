#!/usr/bin/env python3
"""Fetch configured upstream source snapshots into data/raw."""

from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_sources(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [source for source in payload.get("sources", []) if source.get("enabled", True)]


def fetch(url: str, path: Path) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "ASN-Signal-Graph/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return len(payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch ASN Signal Graph upstream source snapshots.")
    parser.add_argument("--sources", default="config/sources.json", type=Path, help="Path to source config JSON.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.sources.parent.parent if args.sources.parent.name == "config" else Path.cwd()
    manifest = {
        "fetched_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "sources": [],
    }

    for source in load_sources(args.sources):
        url = source.get("url")
        if not url:
            continue
        path = Path(source["path"])
        if not path.is_absolute():
            path = root / path
        size = fetch(url, path)
        manifest["sources"].append(
            {
                "id": source["id"],
                "name": source.get("name", source["id"]),
                "category": source.get("category"),
                "format": source.get("format"),
                "url": url,
                "path": str(path),
                "bytes": size,
            }
        )
        print(f"fetched {source['id']} -> {path} ({size} bytes)")

    manifest_path = root / "data/raw/source-fetch-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
