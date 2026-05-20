# ASN Signal Graph Schema

## Source Config

`config/sources.json` contains enabled local feed snapshots:

```json
{
  "id": "asn-vpn-multi-provider",
  "name": "ASN VPN Network Intelligence multi-provider ASN dataset",
  "category": "vpn",
  "format": "asn_vpn_multi_provider_csv",
  "url": "https://raw.githubusercontent.com/ipanalytics/ASN-VPN-Network-Intelligence/main/asn_multi_provider.csv",
  "path": "data/raw/ipanalytics/asn-vpn-network-intelligence/asn_multi_provider.csv",
  "enabled": true
}
```

## Input CSV

All MVP feeds must include:

```csv
asn
```

Recommended columns:

```csv
asn,org,country,signal_count
```

Hosting base feeds can include:

```csv
asn,org,country,prefix_count,ip_count_estimate
```

Real upstream source formats are handled as follows:

- `asn_vpn_multi_provider_csv`: aggregated directly by `ASN`, using `IPs` as `vpn_signals`.
- `tor_radar_network_json`: aggregated from all `relays`, using Tor relay count as `tor_signals`.
- `ip_knowledge_csv`: aggregates rows that already carry `asn`; Tor rows are skipped when Tor-Radar is also configured to avoid double counting.
- `ipverse_as_metadata_csv`: enriches existing ASN records with organization and country.
- `spamhaus_asndrop_jsonl`: aggregates ASNDROP JSONL records as `drop_list_signals`.
- `cidr_csv`: downloaded and indexed, pending local CIDR -> ASN mapping.
- `blackroute_feeds_yaml`: downloaded and indexed as the upstream public-feed source catalog.

## Current Outputs

`data/current/asn-signals.csv`

```csv
asn,org,country,total_prefixes,signal_count,source_count,vpn_signals,tor_signals,malware_signals,drop_list_signals,phishing_signals,public_feed_overlap,signal_density,confidence,sources
```

`data/current/hosting-signal-graph.jsonl`

```json
{
  "asn": 9009,
  "org": "M247",
  "country": "GB",
  "prefix_count": 1240,
  "labels": [
    "vpn-medium",
    "tor-medium",
    "anonymity-overlap-infrastructure"
  ],
  "signals": {
    "vpn": {
      "count": 410,
      "level": "medium",
      "sources": ["asn-vpn-multi-provider"]
    },
    "tor": {
      "count": 12,
      "level": "medium",
      "sources": ["tor-radar-network"]
    }
  },
  "profile": {
    "hosting_type": "vpn-heavy-hosting",
    "infrastructure_role": "anonymity-overlap-infrastructure",
    "signal_count": 573,
    "signal_density": 0.4621,
    "public_feed_overlap": 6,
    "confidence": "high"
  }
}
```

`data/history/summary.csv` keeps compact snapshot history only.

## Static API

Full record:

```text
data/api/asn/<asn>.json
```

Top lists:

```text
data/api/top/vpn.json
data/api/top/tor.json
data/api/top/drop_list.json
data/api/top/drop_list.json
```

Dashboard payload:

```text
data/current/dashboard-data.json
```
