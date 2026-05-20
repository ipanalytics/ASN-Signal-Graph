#!/usr/bin/env python3
"""Build ASN-level public infrastructure signal outputs."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SIGNAL_COLUMNS = {
    "vpn": "vpn_signals",
    "tor": "tor_signals",
    "malware": "malware_signals",
    "drop_list": "drop_list_signals",
    "phishing": "phishing_signals",
    "abuse_config": "public_feed_signals",
    "public_feed": "public_feed_signals",
}

OUTPUT_COLUMNS = [
    "asn",
    "org",
    "country",
    "total_prefixes",
    "signal_count",
    "source_count",
    "vpn_signals",
    "tor_signals",
    "malware_signals",
    "drop_list_signals",
    "phishing_signals",
    "public_feed_signals",
    "public_feed_overlap",
    "signal_density",
    "confidence",
    "sources",
]

SIGNAL_API_KEYS = {
    "vpn": "vpn_signals",
    "tor": "tor_signals",
    "malware": "malware_signals",
    "drop_list": "drop_list_signals",
    "phishing": "phishing_signals",
    "public_feed": "public_feed_signals",
}


@dataclass
class AsnSignal:
    asn: int
    org: str = ""
    country: str = ""
    total_prefixes: int = 0
    ip_count_estimate: int = 0
    signals: dict[str, int] = field(default_factory=lambda: {column: 0 for column in SIGNAL_COLUMNS.values()})
    source_ids: set[str] = field(default_factory=set)
    source_categories: set[str] = field(default_factory=set)

    def add_identity(self, row: dict[str, str]) -> None:
        self.org = self.org or row.get("org", "").strip()
        self.country = self.country or row.get("country", "").strip()
        self.total_prefixes = max(self.total_prefixes, parse_int(row.get("prefix_count", "")))
        self.ip_count_estimate = max(self.ip_count_estimate, parse_int(row.get("ip_count_estimate", "")))

    def add_signal(self, category: str, source_id: str, count: int) -> None:
        column = SIGNAL_COLUMNS.get(category)
        if not column:
            return
        self.signals[column] += max(count, 1)
        self.source_ids.add(source_id)
        self.source_categories.add(category)

    @property
    def signal_count(self) -> int:
        return sum(self.signals.values())

    @property
    def public_feed_overlap(self) -> int:
        return len(self.source_categories)

    @property
    def signal_density(self) -> float:
        denominator = self.total_prefixes or 1
        return round(self.signal_count / denominator, 4)

    @property
    def confidence(self) -> str:
        if self.public_feed_overlap >= 5 and self.signal_count >= 25:
            return "high"
        if self.public_feed_overlap >= 3 and self.signal_count >= 5:
            return "medium"
        return "low"

    def csv_row(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "asn": self.asn,
            "org": self.org,
            "country": self.country,
            "total_prefixes": self.total_prefixes,
            "signal_count": self.signal_count,
            "source_count": len(self.source_ids),
            "public_feed_overlap": self.public_feed_overlap,
            "signal_density": f"{self.signal_density:.4f}",
            "confidence": self.confidence,
            "sources": ",".join(sorted(self.source_ids)),
        }
        row.update(self.signals)
        return row

    def json_record(self) -> dict[str, Any]:
        signals = api_signals(self)
        return {
            "asn": self.asn,
            "org": self.org,
            "country": self.country,
            "prefix_count": self.total_prefixes,
            "ip_count_estimate": self.ip_count_estimate,
            "labels": labels_for(self),
            "profile": {
                "hosting_type": hosting_type_for(self),
                "infrastructure_role": infrastructure_role_for(self),
                "signal_count": self.signal_count,
                "signal_density": self.signal_density,
                "public_feed_overlap": self.public_feed_overlap,
                "confidence": self.confidence,
                "source_count": len(self.source_ids),
                "sources": sorted(self.source_ids),
            },
            "signals": signals,
            "signal_counts": dict(self.signals),
            "disclaimer": (
                "This record describes public infrastructure signals observed in public sources. "
                "It does not classify the provider as malicious."
            ),
        }


def parse_int(value: str | None) -> int:
    if value is None:
        return 0
    value = str(value).strip()
    if not value:
        return 0
    try:
        return int(float(value))
    except ValueError:
        return 0


def load_sources(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return [source for source in payload.get("sources", []) if source.get("enabled", True)]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def get_record(records: dict[int, AsnSignal], asn: int) -> AsnSignal:
    if asn not in records:
        records[asn] = AsnSignal(asn=asn)
    return records[asn]


def aggregate(sources_path: Path) -> tuple[dict[int, AsnSignal], list[dict[str, Any]]]:
    records: dict[int, AsnSignal] = {}
    source_index: list[dict[str, Any]] = []
    root = sources_path.parent.parent if sources_path.parent.name == "config" else Path.cwd()

    for source in load_sources(sources_path):
        source_id = source["id"]
        category = source["category"]
        source_path = Path(source["path"])
        if not source_path.is_absolute():
            source_path = root / source_path

        if not source_path.exists():
            source_index.append(
                {
                    "id": source_id,
                    "name": source.get("name", source_id),
                    "category": category,
                    "format": source.get("format", "csv"),
                    "path": str(source_path),
                    "url": source.get("url"),
                    "observed_asns": 0,
                    "row_count": 0,
                    "status": "missing_local_snapshot",
                }
            )
            continue

        observed_asns, row_count = ingest_source(records, source, source_path)

        source_index.append(
            {
                "id": source_id,
                "name": source.get("name", source_id),
                "category": category,
                "format": source.get("format", "csv"),
                "path": str(source_path),
                "url": source.get("url"),
                "observed_asns": len(observed_asns),
                "row_count": row_count,
                "status": "ok",
            }
        )

    return records, source_index


def ingest_source(records: dict[int, AsnSignal], source: dict[str, Any], source_path: Path) -> tuple[set[int], int]:
    source_format = source.get("format", "csv")
    category = source["category"]
    source_id = source["id"]

    if source_format == "asn_vpn_multi_provider_csv":
        return ingest_asn_vpn_multi_provider(records, source_id, source_path)
    if source_format == "ipverse_as_metadata_csv":
        return ingest_ipverse_as_metadata(records, source_path)
    if source_format == "ip_knowledge_csv":
        return ingest_ip_knowledge(records, source_id, source_path)
    if source_format == "tor_radar_network_json":
        return ingest_tor_radar_network(records, source_id, source_path)
    if source_format == "spamhaus_asndrop_jsonl":
        return ingest_spamhaus_asndrop(records, source_id, source_path)
    if source_format == "provider_cidr_textlist":
        return ingest_provider_cidr_textlist(records, source, source_path)
    if source_format in {"cidr_csv", "blackroute_feeds_yaml", "ip_textlist", "cidr_textlist"}:
        return set(), count_rows(source_path, source_format)

    rows = read_csv(source_path)
    observed_asns: set[int] = set()
    for row in rows:
        asn = parse_int(row.get("asn") or row.get("ASN"))
        if asn <= 0:
            continue
        observed_asns.add(asn)
        record = get_record(records, asn)
        record.add_identity(normalize_identity_row(row))
        if category == "hosting_base":
            continue
        record.add_signal(category, source_id, parse_int(row.get("signal_count")) or 1)
    return observed_asns, len(rows)


def ingest_ipverse_as_metadata(records: dict[int, AsnSignal], source_path: Path) -> tuple[set[int], int]:
    rows = read_csv(source_path)
    observed_asns: set[int] = set()
    for row in rows:
        asn = parse_int(row.get("asn"))
        if asn <= 0 or asn not in records:
            continue
        observed_asns.add(asn)
        records[asn].add_identity(
            {
                "org": row.get("description", ""),
                "country": row.get("country-code", ""),
                "prefix_count": "",
                "ip_count_estimate": "",
            }
        )
    return observed_asns, len(rows)


def ingest_asn_vpn_multi_provider(records: dict[int, AsnSignal], source_id: str, source_path: Path) -> tuple[set[int], int]:
    rows = read_csv(source_path)
    observed_asns: set[int] = set()
    for row in rows:
        asn = parse_int(row.get("ASN"))
        if asn <= 0:
            continue
        observed_asns.add(asn)
        record = get_record(records, asn)
        record.add_identity(
            {
                "org": row.get("Org", "").strip(),
                "country": "",
                "prefix_count": "",
                "ip_count_estimate": normalize_number(row.get("IPs", "")),
            }
        )
        record.add_signal("vpn", source_id, parse_int(normalize_number(row.get("IPs", ""))) or 1)
    return observed_asns, len(rows)


def ingest_ip_knowledge(records: dict[int, AsnSignal], source_id: str, source_path: Path) -> tuple[set[int], int]:
    observed_asns: set[int] = set()
    row_count = 0
    seen_prefix_source: set[tuple[int, str, str]] = set()

    with source_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_count += 1
            asn = parse_int(row.get("asn"))
            if asn <= 0:
                continue

            tags = split_tags(row.get("tags", ""))
            category = category_from_ip_knowledge(row.get("layer", ""), tags)
            if not category:
                continue

            prefix = row.get("prefix", "").strip()
            dedupe_key = (asn, category, prefix)
            if dedupe_key in seen_prefix_source:
                continue
            seen_prefix_source.add(dedupe_key)

            observed_asns.add(asn)
            record = get_record(records, asn)
            record.add_identity(
                {
                    "org": row.get("asn_name", ""),
                    "country": row.get("country", ""),
                    "prefix_count": "",
                    "ip_count_estimate": "",
                }
            )
            record.add_signal(category, source_id, 1)

    return observed_asns, row_count


def ingest_spamhaus_asndrop(records: dict[int, AsnSignal], source_id: str, source_path: Path) -> tuple[set[int], int]:
    observed_asns: set[int] = set()
    row_count = 0
    with source_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row_count += 1
            item = json.loads(line)
            if item.get("type") == "metadata":
                continue
            asn = parse_int(item.get("asn"))
            if asn <= 0:
                continue
            observed_asns.add(asn)
            record = get_record(records, asn)
            record.add_identity(
                {
                    "org": item.get("asname", ""),
                    "country": item.get("cc", ""),
                    "prefix_count": "",
                    "ip_count_estimate": "",
                }
            )
            record.add_signal("drop_list", source_id, 1)
    return observed_asns, row_count


def ingest_tor_radar_network(records: dict[int, AsnSignal], source_id: str, source_path: Path) -> tuple[set[int], int]:
    payload = read_json(source_path)
    observed_asns: set[int] = set()
    asn_counts: dict[int, int] = {}

    for relay in payload.get("relays", []):
        asn = parse_asn(relay.get("asn"))
        if asn <= 0:
            continue
        asn_counts[asn] = asn_counts.get(asn, 0) + 1

    for asn, count in asn_counts.items():
        observed_asns.add(asn)
        record = get_record(records, asn)
        record.add_signal("tor", source_id, count)

    for relay in payload.get("relays", []):
        asn = parse_asn(relay.get("asn"))
        if asn <= 0 or asn not in records:
            continue
        record = records[asn]
        if not record.org:
            record.org = relay.get("asName", "") if relay.get("asName") != "unknown" else ""
        if not record.country and record.source_categories == {"tor"}:
            record.country = relay.get("country", "")

    return observed_asns, len(payload.get("relays", []))


def ingest_provider_cidr_textlist(
    records: dict[int, AsnSignal],
    source: dict[str, Any],
    source_path: Path,
) -> tuple[set[int], int]:
    source_id = source["id"]
    category = source["category"]
    metadata_path = source.get("asn_metadata_path")
    if not metadata_path:
        return set(), count_rows(source_path, "cidr_textlist")

    metadata = Path(metadata_path)
    if not metadata.is_absolute():
        metadata = source_path.parents[3] / metadata
    if not metadata.exists():
        return set(), count_rows(source_path, "cidr_textlist")

    name_index = load_asn_name_index(metadata)
    observed_asns: set[int] = set()
    row_count = 0

    with source_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text or text.startswith(("#", ";")):
                continue
            row_count += 1
            parts = re.split(r"\s+", text, maxsplit=1)
            if len(parts) < 2:
                continue
            provider_key = normalize_provider_name(parts[1])
            if not provider_key:
                continue
            for asn, identity in name_index.get(provider_key, []):
                observed_asns.add(asn)
                record = get_record(records, asn)
                record.add_identity(identity)
                record.add_signal(category, source_id, 1)

    return observed_asns, row_count


def load_asn_name_index(metadata_path: Path) -> dict[str, list[tuple[int, dict[str, str]]]]:
    index: dict[str, list[tuple[int, dict[str, str]]]] = {}
    for row in read_csv(metadata_path):
        asn = parse_int(row.get("asn"))
        if asn <= 0:
            continue
        identity = {
            "org": row.get("description", ""),
            "country": row.get("country-code", ""),
            "prefix_count": "",
            "ip_count_estimate": "",
        }
        for value in {row.get("handle", ""), row.get("description", "")}:
            key = normalize_provider_name(value)
            if not key:
                continue
            index.setdefault(key, []).append((asn, identity))
    return index


def normalize_identity_row(row: dict[str, str]) -> dict[str, str]:
    return {
        "org": row.get("org") or row.get("Org") or "",
        "country": row.get("country") or row.get("Country") or "",
        "prefix_count": row.get("prefix_count") or row.get("PrefixCount") or "",
        "ip_count_estimate": row.get("ip_count_estimate") or row.get("IPs") or "",
    }


def normalize_number(value: str | None) -> str:
    return str(value or "").replace(",", "").strip()


def parse_asn(value: Any) -> int:
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return parse_int(text)


def split_tags(value: str) -> set[str]:
    return {tag.strip().lower() for tag in value.split("|") if tag.strip()}


def normalize_provider_name(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", str(value).lower())
    words = [
        word
        for word in text.split()
        if word
        and word
        not in {
            "as",
            "asn",
            "inc",
            "llc",
            "ltd",
            "limited",
            "gmbh",
            "sas",
            "srl",
            "corp",
            "corporation",
            "company",
            "co",
            "plc",
            "bv",
            "ag",
            "online",
        }
    ]
    return "".join(words)


def category_from_ip_knowledge(layer: str, tags: set[str]) -> str:
    layer = layer.strip().lower()
    if "tor" in tags:
        return ""
    if "vpn" in tags or "proxy" in tags or layer == "anonymity":
        return "vpn"
    return ""


def level_for(count: int, signal_key: str) -> str:
    if count <= 0:
        return "none"
    high_thresholds = {
        "vpn": 500,
        "tor": 100,
        "malware": 25,
        "drop_list": 1,
        "phishing": 25,
        "public_feed": 5,
    }
    medium_thresholds = {
        "vpn": 50,
        "tor": 10,
        "malware": 5,
        "drop_list": 1,
        "phishing": 5,
        "public_feed": 2,
    }
    if count >= high_thresholds.get(signal_key, 100):
        return "high"
    if count >= medium_thresholds.get(signal_key, 10):
        return "medium"
    return "low"


def sources_for_signal(record: AsnSignal, signal_key: str) -> list[str]:
    if record.signals.get(SIGNAL_API_KEYS[signal_key], 0) <= 0:
        return []
    if signal_key == "vpn":
        return sorted(source for source in record.source_ids if source in {"asn-vpn-multi-provider", "ip-knowledge-layer"})
    if signal_key == "tor":
        return sorted(source for source in record.source_ids if source == "tor-radar-network")
    if signal_key == "drop_list":
        return sorted(source for source in record.source_ids if source == "spamhaus-asndrop")
    return sorted(record.source_ids)


def api_signals(record: AsnSignal) -> dict[str, dict[str, Any]]:
    return {
        key: {
            "count": record.signals[column],
            "level": level_for(record.signals[column], key),
            "sources": sources_for_signal(record, key),
        }
        for key, column in SIGNAL_API_KEYS.items()
    }


def hosting_type_for(record: AsnSignal) -> str:
    if record.signals["vpn_signals"] >= 500:
        return "vpn-heavy-hosting"
    if record.signals["tor_signals"] >= 100:
        return "tor-heavy-hosting"
    if record.signals["drop_list_signals"] > 0:
        return "public-feed-listed-asn"
    return "infrastructure-observed"


def infrastructure_role_for(record: AsnSignal) -> str:
    active = [
        key
        for key, column in SIGNAL_API_KEYS.items()
        if key != "public_feed" and record.signals.get(column, 0) > 0
    ]
    if len(active) >= 3:
        return "mixed-signal-infrastructure"
    if record.signals["vpn_signals"] > 0 and record.signals["tor_signals"] > 0:
        return "anonymity-overlap-infrastructure"
    if record.signals["vpn_signals"] > 0:
        return "vpn-overlap-infrastructure"
    if record.signals["tor_signals"] > 0:
        return "tor-overlap-infrastructure"
    if record.signals["drop_list_signals"] > 0:
        return "public-feed-listed-infrastructure"
    return "observed-infrastructure"


def labels_for(record: AsnSignal) -> list[str]:
    labels: list[str] = []
    for key, column in SIGNAL_API_KEYS.items():
        if key == "public_feed":
            continue
        level = level_for(record.signals[column], key)
        if level != "none":
            labels.append(f"{key}-{level}")
    if record.public_feed_overlap >= 3:
        labels.append("multi-source-overlap")
    labels.append(infrastructure_role_for(record))
    return labels


def count_rows(path: Path, source_format: str) -> int:
    if source_format == "cidr_csv":
        return max(len(read_csv(path)), 0)
    if source_format == "blackroute_feeds_yaml":
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip().startswith("- kind:"):
                    count += 1
        return count
    if source_format in {"ip_textlist", "cidr_textlist", "provider_cidr_textlist"}:
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if text and not text.startswith(("#", ";")):
                    count += 1
        return count
    return 0


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_outputs(records: dict[int, AsnSignal], source_index: list[dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = [record.csv_row() for record in sorted(records.values(), key=lambda item: (-item.signal_count, item.asn))]

    write_csv(output_dir / "asn-signals.csv", rows, OUTPUT_COLUMNS)
    write_csv(output_dir / "top-hosting-footprints.csv", rows[:100], OUTPUT_COLUMNS)

    overlap_rows = [
        {
            "asn": row["asn"],
            "org": row["org"],
            "country": row["country"],
            "vpn_signals": row["vpn_signals"],
            "tor_signals": row["tor_signals"],
            "public_feed_overlap": row["public_feed_overlap"],
            "confidence": row["confidence"],
            "sources": row["sources"],
        }
        for row in rows
        if row["vpn_signals"] or row["tor_signals"]
    ]
    write_csv(
        output_dir / "provider-overlap.csv",
        overlap_rows,
        ["asn", "org", "country", "vpn_signals", "tor_signals", "public_feed_overlap", "confidence", "sources"],
    )

    with (output_dir / "hosting-signal-graph.jsonl").open("w", encoding="utf-8") as handle:
        for record in sorted(records.values(), key=lambda item: item.asn):
            handle.write(json.dumps(record.json_record(), sort_keys=True) + "\n")

    write_static_api(records, source_index, rows, output_dir)

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    summary = {
        "generated_at": generated_at,
        "asn_count": len(records),
        "total_signals": sum(record.signal_count for record in records.values()),
        "source_count": len(source_index),
        "malware_asns": count_asns_with(records, "malware_signals"),
        "vpn_asns": count_asns_with(records, "vpn_signals"),
        "tor_asns": count_asns_with(records, "tor_signals"),
        "top_signal_asn": rows[0]["asn"] if rows else None,
    }

    with (output_dir / "source-index.json").open("w", encoding="utf-8") as handle:
        json.dump({"generated_at": generated_at, "sources": source_index}, handle, indent=2, sort_keys=True)
        handle.write("\n")

    with (output_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")

    history_dir = output_dir.parent / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_path = history_dir / "summary.csv"
    history_exists = history_path.exists()
    with history_path.open("a", encoding="utf-8", newline="") as handle:
        fieldnames = ["timestamp", "asn_count", "total_signals", "malware_asns", "vpn_asns", "tor_asns", "top_signal_asn"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not history_exists:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": generated_at,
                "asn_count": summary["asn_count"],
                "total_signals": summary["total_signals"],
                "malware_asns": summary["malware_asns"],
                "vpn_asns": summary["vpn_asns"],
                "tor_asns": summary["tor_asns"],
                "top_signal_asn": summary["top_signal_asn"],
            }
        )


def count_asns_with(records: dict[int, AsnSignal], signal_column: str) -> int:
    return sum(1 for record in records.values() if record.signals.get(signal_column, 0) > 0)


def write_static_api(
    records: dict[int, AsnSignal],
    source_index: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    output_dir: Path,
) -> None:
    api_dir = output_dir.parent / "api"
    asn_dir = api_dir / "asn"
    top_dir = api_dir / "top"
    country_dir = api_dir / "country"
    for directory in [asn_dir, top_dir, country_dir]:
        directory.mkdir(parents=True, exist_ok=True)
    for stale in ["crawler.json", "scanner.json"]:
        stale_path = top_dir / stale
        if stale_path.exists():
            stale_path.unlink()

    api_records = [record.json_record() for record in sorted(records.values(), key=lambda item: (-item.signal_count, item.asn))]
    compact_records = [compact_record(record) for record in sorted(records.values(), key=lambda item: (-item.signal_count, item.asn))]

    write_json(api_dir / "index.json", {"records": compact_records, "source_count": len(source_index)})
    write_json(api_dir / "signals.json", {"records": compact_records})
    write_json(api_dir / "sources.json", {"sources": source_index})

    for record in records.values():
        write_json(asn_dir / f"{record.asn}.json", record.json_record())

    for key, column in SIGNAL_API_KEYS.items():
        ranked = [
            compact_record(record)
            for record in sorted(records.values(), key=lambda item: (-item.signals[column], item.asn))
            if record.signals[column] > 0
        ][:100]
        write_json(top_dir / f"{key}.json", {"signal": key, "records": ranked})

    country_groups: dict[str, list[AsnSignal]] = {}
    for record in records.values():
        country = record.country or "ZZ"
        country_groups.setdefault(country, []).append(record)
    for country, group in country_groups.items():
        ranked = [compact_record(record) for record in sorted(group, key=lambda item: (-item.signal_count, item.asn))]
        write_json(country_dir / f"{country}.json", {"country": country, "records": ranked})

    write_json(
        output_dir / "dashboard-data.json",
        {
            "records": compact_records,
            "sources": source_index,
            "top": compact_records[:100],
            "disclaimer": "Public infrastructure signal aggregation. No provider maliciousness classification.",
        },
    )


def compact_record(record: AsnSignal) -> dict[str, Any]:
    return {
        "asn": record.asn,
        "org": record.org,
        "country": record.country or "ZZ",
        "signal_count": record.signal_count,
        "source_count": len(record.source_ids),
        "public_feed_overlap": record.public_feed_overlap,
        "confidence": record.confidence,
        "hosting_type": hosting_type_for(record),
        "infrastructure_role": infrastructure_role_for(record),
        "labels": labels_for(record),
        "signals": {
            key: {
                "count": record.signals[column],
                "level": level_for(record.signals[column], key),
            }
            for key, column in SIGNAL_API_KEYS.items()
        },
        "sources": sorted(record.source_ids),
    }


def write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build ASN-level ASN Signal Graph outputs.")
    parser.add_argument("--sources", default="config/sources.json", type=Path, help="Path to source config JSON.")
    parser.add_argument("--output-dir", default="data/current", type=Path, help="Directory for current outputs.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records, source_index = aggregate(args.sources)
    write_outputs(records, source_index, args.output_dir)
    print(f"wrote {len(records)} ASN records to {args.output_dir}")


if __name__ == "__main__":
    main()
