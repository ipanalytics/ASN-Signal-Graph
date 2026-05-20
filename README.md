# ASN Signal Graph



<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-CC0--1.0-blue" alt="License">
  </a>
  <a href="https://github.com/ipanalytics/ASN-Signal-Graph/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/ipanalytics/ASN-Signal-Graph/build.yml?branch=main" alt="CI">
  </a>
  <a href="https://github.com/ipanalytics/ASN-Signal-Graph">
    <img src="https://img.shields.io/github/last-commit/ipanalytics/ASN-Signal-Graph" alt="Last Commit">
  </a>
  <a href="https://github.com/ipanalytics/ASN-Signal-Graph">
    <img src="https://img.shields.io/badge/dataset-active-success" alt="Dataset">
  </a>
  <a href="https://github.com/ipanalytics/ASN-Signal-Graph">
    <img src="https://img.shields.io/badge/exports-csv%20%7C%20jsonl-informational" alt="Exports">
  </a>
  <a href="https://github.com/ipanalytics/ASN-Signal-Graph">
    <img src="https://img.shields.io/badge/focus-infrastructure_signals-informational" alt="Focus">
  </a>
</p>

---

ASN Signal Graph is a public ASN infrastructure signal aggregation project for enrichment, research, and defensive analytics.

The repository aggregates observable public infrastructure signals at ASN level and publishes normalized profiles describing VPN overlap, Tor presence, public feed exposure, DROP-listed infrastructure overlap, and source diversity.

The project intentionally frames outputs as infrastructure context rather than provider reputation or maliciousness classification.

---

## Overview

Modern hosting and network infrastructure frequently overlaps across:

* VPN providers
* Tor relays
* public abuse feeds
* crawler infrastructure
* cloud and VPS platforms
* public blocklists

ASN Signal Graph aggregates those observable signals into lightweight operational profiles suitable for:

* fraud detection
* SIEM enrichment
* infrastructure research
* routing analytics
* abuse-prevention workflows
* network intelligence pipelines

The repository does not classify providers as malicious or assign enforcement verdicts.

---

## Signal Model

The primary object is an ASN profile:

```text id="jlwm42"
ASN / organization / country
    -> vpn overlap
    -> tor overlap
    -> drop-list overlap
    -> public feed overlap
    -> signal density
    -> source diversity
    -> confidence
```

Example output:

```csv id="jlwm43"
asn,org,country,total_prefixes,signal_count,source_count,vpn_signals,tor_signals,abuse_feed_overlap,drop_list_overlap,public_feed_overlap,signal_density,confidence,sources
9009,M247,RO,0,4922,3,4861,52,0,0,9,4922.0000,medium,"asn-vpn-multi-provider,bad-cidrs-v4,tor-radar-network"
```

Signal counts represent overlap with public datasets and infrastructure observations. They are intended as enrichment features, not provider verdicts.

---

## Architecture

```text id="jlwm44"
              Public Infrastructure Sources
                              │
      ┌───────────────────────┼────────────────────────┐
      │                       │                        │
      ▼                       ▼                        ▼
   VPN Signals            Tor Signals           Public Feeds
      │                       │                        │
      └───────────────────────┴─────────────┬──────────┘
                                            ▼
                                  ASN Aggregation Layer
                               normalize / correlate / score
                                            ▼
                                     Signal Profiles
                                            ▼
                           CSV / JSONL / static API / dashboard
```

---

## Data Sources

Configured sources are defined in:

```text id="jlwm45"
config/sources.json
```

Current inputs include:

| Source                         | Purpose                    |
| ------------------------------ | -------------------------- |
| `IP-Knowledge-Layer`           | Infrastructure enrichment  |
| `ASN-VPN-Network-Intelligence` | VPN ASN overlap            |
| `Tor-Radar`                    | Tor relay visibility       |
| `blackroute`                   | Public feed catalog        |
| Spamhaus ASNDROP               | ASN-level DROP exposure    |
| `stamparm/ipsum`               | Public reputation overlap  |
| `saloniamatteo/bad-cidrs`      | Public CIDR overlap        |
| `ipverse/as-metadata`          | ASN enrichment and mapping |

ASN-native feeds are aggregated directly.

Provider-labeled CIDR feeds are mapped through normalized provider metadata. IP-only feeds are indexed separately until reliable IP/CIDR-to-ASN mapping is available.

---

## Published Outputs

| File                                      | Description                  |
| ----------------------------------------- | ---------------------------- |
| `data/current/asn-signals.csv`            | Flat ASN signal export       |
| `data/current/hosting-signal-graph.jsonl` | Full JSONL signal profiles   |
| `data/current/provider-overlap.csv`       | Provider overlap aggregates  |
| `data/current/source-index.json`          | Source metadata and indexing |
| `data/current/summary.json`               | Snapshot summary             |
| `data/current/dashboard-data.json`        | Dashboard dataset            |
| `data/api/index.json`                     | Static API index             |
| `data/api/asn/<asn>.json`                 | ASN detail API               |
| `data/api/top/<signal>.json`              | Top ASN signal rankings      |
| `data/api/country/<country>.json`         | Country-level views          |

The API is fully static and can be hosted directly from GitHub Pages.

---

## Dashboard

The repository includes a static browser dashboard under:

```text id="jlwm46"
site/
```

Features include:

* ASN search by number or organization
* country and signal filtering
* sortable signal tables
* minimum signal thresholds
* confidence filtering
* clickable summary metrics
* ASN detail panels
* direct JSON export links

The dashboard is fully backend-free.

---

## Signal Semantics

Signal levels describe observed infrastructure overlap volume, not provider reputation.

| Level    | Meaning                |
| -------- | ---------------------- |
| `none`   | No observed overlap    |
| `low`    | Small observed overlap |
| `medium` | Moderate overlap       |
| `high`   | Large observed overlap |

### Confidence

Confidence measures data completeness and source diversity.

| Confidence | Requirements                       |
| ---------- | ---------------------------------- |
| `high`     | ≥5 source families and ≥25 signals |
| `medium`   | ≥3 source families and ≥5 signals  |
| `low`      | Below medium threshold             |

Confidence is not a badness score.

---

## Quick Start

Fetch upstream datasets:

```bash id="jlwm47"
python3 scripts/fetch_sources.py \
  --sources config/sources.json
```

Build current outputs:

```bash id="jlwm48"
python3 scripts/build_signal_graph.py \
  --sources config/sources.json \
  --output-dir data/current
```

Serve locally:

```bash id="jlwm49"
python3 -m http.server 8000
```

Open:

```text id="jlwm50"
http://127.0.0.1:8000/site/
```

---

## GitHub Actions

| Workflow                 | Purpose                                                    |
| ------------------------ | ---------------------------------------------------------- |
| `Test`                   | Validate snapshots, CSV/JSON outputs, and dashboard builds |
| `Build ASN Signal Graph` | Scheduled/manual upstream refresh and aggregation          |
| `Deploy Pages`           | Publish static dashboard and API                           |

The project is designed for GitHub-native static deployment workflows.

---

## Operational Notes

* Large cloud and VPS providers frequently appear in public overlap feeds because of scale and customer diversity
* Public feed overlap should be interpreted alongside source diversity and signal mix
* IP-only feeds require reliable ASN mapping before contributing weighted ASN counts
* Signal density reflects observed infrastructure exposure, not intent or ownership

---

## Design Principles

| Principle              | Description                                         |
| ---------------------- | --------------------------------------------------- |
| Neutral Framing        | Infrastructure context instead of provider verdicts |
| Reproducibility        | Deterministic snapshot generation                   |
| Lightweight Deployment | Fully static outputs and API                        |
| Source Transparency    | Preserve provenance and source diversity            |
| Operational Utility    | Useful for enrichment and analytics workflows       |

---

## Recommended Interpretation

Preferred terminology:

* observed signals
* infrastructure overlap
* source diversity
* public feed exposure
* infrastructure context
* confidence

Avoid:

* malicious ASN
* bad provider
* criminal hosting
* definitive attribution
* enforcement verdicts

The project publishes observable infrastructure correlations derived from public datasets.

---

## Use Cases

| Domain            | Example                             |
| ----------------- | ----------------------------------- |
| Fraud Detection   | VPN and Tor enrichment              |
| SIEM Pipelines    | ASN infrastructure context          |
| Network Analytics | Hosting concentration analysis      |
| Abuse Prevention  | Public feed overlap review          |
| Research          | Infrastructure relationship mapping |
| Routing Analysis  | ASN signal clustering               |

---

## Repository Layout

```text id="jlwm51"
.
├── config/
├── data/
│   ├── api/
│   └── current/
├── scripts/
├── site/
├── LICENSE
└── README.md
```

---

## Roadmap

Planned additions:

* ASN delta tracking
* signal-family clustering
* IPv6 overlap support
* ASN relationship graphing
* compact historical summaries
* infrastructure topology metrics

---

## License

Licensed under CC0-1.0.

See [`LICENSE`](./LICENSE).

---

## Disclaimer

ASN Signal Graph aggregates publicly observable infrastructure signals for analytical and operational use. The project does not classify providers as malicious and should not be used as a standalone enforcement or attribution system.
