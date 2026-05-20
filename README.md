# ASN Signal Graph

Public ASN infrastructure signal aggregation for enrichment, research, and defensive analytics.

This project does not classify hosting providers as malicious. It aggregates observable public signals at ASN level and keeps the output framed as infrastructure context: overlap with VPN networks, Tor relays, DROP-listed ASNs, and public IP/CIDR feed exposure.

## What It Publishes

The primary object is an ASN profile:

```text
ASN / organization / country
  -> vpn_signals
  -> tor_signals
  -> drop_list_signals
  -> public_feed_signals
  -> signal_density
  -> confidence
  -> sources
```

Example CSV row:

```csv
asn,org,country,total_prefixes,signal_count,source_count,vpn_signals,tor_signals,malware_signals,drop_list_signals,phishing_signals,public_feed_signals,public_feed_overlap,signal_density,confidence,sources
9009,M247,RO,0,4922,3,4861,52,0,0,0,9,3,4922.0000,medium,"asn-vpn-multi-provider,bad-cidrs-v4,tor-radar-network"
```

`malware_signals` and `phishing_signals` are present in the schema for future feeds. In the current snapshot they may be zero if no configured source can map those IP-only feeds to ASN records yet.

## Data Sources

Configured sources live in `config/sources.json`.

Current inputs include:

- `ipanalytics/IP-Knowledge-Layer`
- `ipanalytics/ASN-VPN-Network-Intelligence`
- `ipanalytics/Tor-Radar`
- `ipanalytics/blackroute` feed catalog
- Spamhaus ASNDROP
- `stamparm/ipsum` levels 3 and 5
- `saloniamatteo/bad-cidrs`
- `ipverse/as-metadata`

ASN-native feeds are aggregated directly. Provider-labeled CIDR feeds, such as `bad-cidrs`, are mapped through `ipverse/as-metadata` by normalized provider labels. Plain IP-only feeds, such as `ipsum`, are downloaded and indexed in `source-index.json`; they need a local IP/CIDR to ASN lookup index before they can contribute reliable ASN-level counts.

`public_feed_signals` means overlap with public IP/CIDR lists. It is not automatically negative by itself: large cloud and hosting networks can appear because they are large, frequently abused by customers, or broadly represented in public lists. Treat it as a context feature and compare it with source count, Tor/VPN overlap, DROP presence, and confidence.

## Outputs

```text
data/current/asn-signals.csv
data/current/hosting-signal-graph.jsonl
data/current/provider-overlap.csv
data/current/source-index.json
data/current/summary.json
data/current/dashboard-data.json
data/api/index.json
data/api/asn/<asn>.json
data/api/top/<signal>.json
data/api/country/<country>.json
```

The static API is backend-free and can be served directly from GitHub Pages.

## Dashboard

`site/` contains a static dashboard for the current snapshot:

- ASN search by number or organization.
- Filters for signal type, level, country, source count, and minimum signal count.
- Sort tabs for total, VPN, Tor, DROP, and public-feed exposure.
- Click-to-sort table columns.
- Clickable summary metrics.
- ASN detail panel with a direct JSON link.
- Reset button for quickly returning to the full matrix.

## Signal Levels

Levels describe observed signal volume, not provider reputation:

- `none`: no observed signal in that category.
- `low`: small observed overlap.
- `medium`: moderate observed overlap.
- `high`: large observed overlap.

Confidence is derived from source diversity and signal volume:

- `high`: at least 5 source families and 25 observed signals.
- `medium`: at least 3 source families and 5 observed signals.
- `low`: anything below medium.

Confidence is a data completeness indicator, not a badness score.

## Quick Start

Fetch upstream snapshots and build current outputs:

```bash
python3 scripts/fetch_sources.py --sources config/sources.json
python3 scripts/build_signal_graph.py --sources config/sources.json --output-dir data/current
```

Serve the dashboard locally:

```bash
python3 -m http.server 8000
```

Open:

```text
http://127.0.0.1:8000/site/
```

## GitHub Actions

- `Test`: compiles scripts, rebuilds from committed snapshots, and validates generated CSV/JSON/dashboard files.
- `Build ASN Signal Graph`: scheduled/manual upstream refresh and build validation.
- `Deploy Pages`: builds the static API and dashboard, then publishes it to GitHub Pages.

## Project Framing

Use neutral wording when describing the data:

- observed signals
- signal density
- public feed overlap
- infrastructure context
- source count
- confidence

Avoid provider verdict language. The project reports public infrastructure signals; it does not label providers as good, bad, criminal, or malicious.
