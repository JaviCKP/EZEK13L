# EZEK13L

**Network Detection & Response — Local Lab**

> A proof-of-concept. Synthetic traffic, virtual hosts, no production claims.  
> What it does demonstrate: a multi-layer detection architecture that reads behaviour, not just signatures.

[IMAGE: dark terminal screenshot showing the blind test output — all five PASS lines in sequence, clean monospace font on black background]

---

## Table of contents

- [The idea](#the-idea)
- [Architecture](#architecture)
- [Network topology](#network-topology)
- [Detection layers](#detection-layers)
- [Attack families](#attack-families)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Blind Generalization Test](#blind-generalization-test)
- [Feature engineering](#feature-engineering)
- [Repository structure](#repository-structure)
- [Limitations](#limitations)
- [What comes next](#what-comes-next)

---

## The idea

Most IDS demos stop at Suricata firing on a known payload. EZEK13L goes one layer deeper.

It combines signature detection (Suricata), unsupervised anomaly scoring (HalfSpaceTrees), supervised attack classification (centroid-based), and hand-tuned behavioural heuristics — four layers that compensate for each other's blind spots. When one layer misses, another doesn't.

The blind generalization test at the end of this document shows what that means in practice.

---

## Architecture

```
  TRAFFIC
  ───────
  simulation/generate_normal.py        simulation/inject_attack.py
  benign: admin · dev · RRHH hosts     5 attack families · 2 generators

          │
          │  .pcap
          ▼

  PROCESSING
  ──────────
  ┌─────────────┐    ┌──────────────┐
  │    Zeek     │    │   Suricata   │
  │  conn.log   │    │  eve.json    │
  │  http.log   │    │  (alerts)    │
  │  dns.log    │    └──────────────┘
  │  tls.log    │
  └─────────────┘

          │
          │  152 features / flow
          ▼

  SCORING                                              pipeline/score.py
  ───────
  ┌──────────────────────────────────────────────┐
  │  Layer 1 — Baseline anomaly (unsupervised)   │
  │  MinMaxScaler + HalfSpaceTrees               │
  │  threshold 0.95 · 99 ratio/shape features    │
  ├──────────────────────────────────────────────┤
  │  Layer 2 — Attack classifier (supervised)    │
  │  CentroidAttackClassifier · 6 classes        │
  │  confidence threshold 0.45                   │
  ├──────────────────────────────────────────────┤
  │  Layer 3 — Expert signals (heuristics)       │
  │  scan pressure · DNS entropy                 │
  │  HTTP shape · volume spike                   │
  ├──────────────────────────────────────────────┤
  │  Layer 4 — Suricata correlation              │
  │  alert cross-reference by IP + flow          │
  └──────────────────────────────────────────────┘

          │
          ▼

  OUTPUT
  ──────
  output/live_scores.jsonl      per-flow scores + labels + audit
  VALIDACION_POC.md             standard validation matrix
  BLIND_TEST_RESULTS.md         generalization test results
```

---

## Network topology

```
192.168.50.0/24
  ├── .10   pc_admin      web browsing, report downloads
  ├── .11   pc_dev        API calls, TLS, DNS
  ├── .12   pc_rrhh       file shares, uploads
  ├── .1    srv_web       internal web/API server
  ├── .2    srv_dns       DNS resolver
  └── .254  gateway       TLS egress

10.0.0.99      attacker        (standard attacks)
172.16.0.50    blind_attacker  (blind test — never seen during training)
```

[IMAGE: clean network topology diagram — dark background, fine lines, node icons for each host, gold accent on the attacker nodes]

---

## Detection layers

### Layer 1 — Unsupervised baseline

Algorithm: `river.anomaly.HalfSpaceTrees` (50 trees · height 10 · window 512)  
Trained on 8 979 events of normal traffic. Threshold: **0.95** (99.9th percentile of calibration holdout).

Features use **ratios instead of raw counters** (`error_ratio_60s` rather than `failed_conn_count_60s`) so the model is not thrown off by volume differences between environments.

Online learning is blocked when a flow scores above 0.75, when Suricata alerts on it, or when the classifier already flagged it — anti-poisoning by design.

### Layer 2 — Supervised classifier

Algorithm: `CentroidAttackClassifier` — centroid k-NN with softmax temperature scaling (T=0.35)  
Trained on 2 460 labelled synthetic events across 6 classes.

| Class | Train samples | Test F1 |
|---|---:|---:|
| normal | 1 800 | 0.998 |
| port_scan | 643 | 1.000 |
| brute_force_http | 421 | 1.000 |
| dns_exfiltration | 286 | 0.993 |
| sql_injection | 117 | 1.000 |
| data_exfiltration | 12 | 0.857 |

These metrics are on synthetic in-distribution test data. The [blind test](#blind-generalization-test) is the more honest number.

### Layer 3 — Expert signals

Four behavioural detectors that run independent of ML scores and produce an auditable `behavioral_factors` label:

| Signal | Condition |
|---|---|
| `scan_ports_60s` / `scan_ports_300s` | 8+ unique destination ports · 4+ failures in 60 s |
| `dns_query_shape` / `dns_nxdomain` | NXDOMAIN responses + query entropy > 4.1 |
| `http_payload_shape` / `http_error_response` | URI entropy > 4.8 or query string > 80 chars |
| `volume_spike` | Single flow > 500 KB or source total > 1 MB in 300 s |

### Layer 4 — Suricata correlation

Standard community ruleset. Alerts from `eve.json` are cross-referenced by IP and flow. A Suricata detection permanently blocks online learning on that IP/flow.

---

## Attack families

Five synthetic attack types, two generators.

| # | Family | Technique |
|---|---|---|
| 1 | Port Scan | SYN scan · RST-ACK responses · sequential or service ports |
| 2 | DNS Exfiltration | High-entropy subdomain labels · NXDOMAIN responses |
| 3 | Brute Force HTTP | Rapid POST · 401 responses · repeated auth attempts |
| 4 | SQL Injection | GET with embedded SQL payloads · UNION / WAITFOR / CAST |
| 5 | Data Exfiltration | Large POST body · single flow or repeated chunks |

`simulation/common.py` — standard generator (training parameters)  
`simulation/blind_attacks.py` — blind generator (disjoint parameters, never seen during training)

---

## Prerequisites

- Docker Desktop (Windows) — `docker-users` group configured
- PowerShell 5.1+

---

## Usage

**Train**
```powershell
.\scripts\poc-train.ps1
```
Generates normal PCAPs → Zeek → features → trains HalfSpaceTrees baseline and CentroidAttackClassifier → writes to `model/`.

**Standard validation**
```powershell
.\scripts\validate-poc.ps1
```
Control + 5 attacks through the full pipeline. Writes `VALIDACION_POC.md`.

```powershell
.\scripts\validate-poc.ps1 -RequireMl   # strict: ML must detect, not just Suricata or heuristics
```

**Blind generalization test**
```powershell
.\scripts\validate-blind.ps1
```
Same 5 families, different IPs / domains / endpoints / payloads. No retraining. Writes `BLIND_TEST_RESULTS.md`.

**Quick demo**
```powershell
.\scripts\demo-jefe.ps1
```
Normal baseline + one attack per family in sequence. ~90 seconds.

**Manual attack injection**
```powershell
docker compose run --rm py python simulation/inject_attack.py       # standard
docker compose run --rm py python simulation/inject_blind_attack.py # blind variants
```

---

## Blind Generalization Test

The standard validation trains and evaluates on the same generator — it measures in-distribution accuracy, not generalisation. To stress-test the model, a second generator was built with entirely different parameters. The model was not retrained.

[IMAGE: side-by-side comparison of VALIDACION_POC.md and BLIND_TEST_RESULTS.md tables, highlighting that the same 5 attacks pass in both — dark background, gold table borders]

### Parameter delta

| Parameter | Standard (training) | Blind (unseen) |
|---|---|---|
| Attacker IP | `10.0.0.99` | `172.16.0.50` |
| Port scan range | Ports 20–99, sequential | Windows service ports: 135, 139, 445, 1433, 3389, 5432 … |
| DNS C2 domain | `*.evil-c2.com` | `*.cdn-update.net` |
| DNS label length | 18 + 18 + 14 chars | 12 + 12 chars |
| Brute force endpoint | `POST /login` | `POST /api/auth/token` |
| Brute force body format | `username=admin&password=…` | `{"user":"svc","secret":"…"}` |
| SQL payloads | UNION SELECT · OR 1=1 · sleep() | WAITFOR DELAY · xp_cmdshell · CAST · DROP TABLE |
| Data exfil | Single POST 650 KB – 3 MB to `/sync` | 3–6 chunks of 100–400 KB to `/api/v2/upload` |

### Results

```
[PASS] Control benigno       raw=0.920  detections=0   layers=—
[PASS] Port Scan             raw=0.851  detections=16  layers=ML, Expert, Suricata
[PASS] DNS Exfiltration      raw=0.794  detections=19  layers=ML, Expert
[PASS] Brute Force HTTP      raw=0.852  detections=17  layers=ML, Suricata
[PASS] SQL Injection         raw=0.818  detections=8   layers=ML, Expert, Suricata
[PASS] Data Exfiltration     raw=0.931  detections=0   layers=Expert

Blind result: 5/5 attacks detected
```

[IMAGE: actual terminal screenshot of validate-blind.ps1 output — monospace, dark background, each PASS line visible]

### What the results show

Each attack was caught by a different combination of layers. That is the point.

**Port Scan** — ML + Expert + Suricata. SYN scan behaviour (many short connections, RST-ACK) is structurally the same regardless of which ports are targeted. All three layers fire independently.

**DNS Exfiltration** — ML + Expert, no Suricata. The community ruleset has no signature for `cdn-update.net`. The classifier catches it through DNS shape features: entropy, NXDOMAIN ratio, rejected query rate. A domain the model has never seen, detected by behaviour alone.

**Brute Force HTTP** — ML + Suricata, no expert signal. The heuristic watches `/login`; `/api/auth/token` does not trigger it. The classifier catches the pattern through POST error rate and connection frequency in the 60 s window.

**SQL Injection** — ML + Expert + Suricata. MSSQL-style payloads (WAITFOR, xp_cmdshell, CAST) are syntactically different from training payloads (UNION, OR 1=1) but share the same feature signature: long URIs, high character entropy, special characters. Shape is invariant to specific keywords.

**Data Exfiltration** — Expert signal only. The ML classifier does not fire — same result as in the standard validation. Twelve training examples for this class is not enough. The volume spike heuristic covers it. This is the honest weak spot of the current model.

---

## Feature engineering

`pipeline/build_features.py` extracts 152 features per flow. The baseline model uses 99 (ratios and shape only — raw volume counts are excluded to avoid environment-specific overfitting).

```
Base (per flow)     duration · bytes/packet ratios · protocol flags · connection state flags
HTTP                URI entropy · query length · special chars · status code flags · body size
DNS                 query entropy · label count · NXDOMAIN flag · answer count · rejected flag
TLS                 SNI length · version flags · resumed · established
Temporal 60s+300s   error ratio · unique IP/port ratio · bytes per conn · POST ratio ·
                    POST error ratio — per source and per src-dst pair
```

[IMAGE: grouped bar chart showing which feature categories contribute most to detection per attack family — dark background, gold bars, one colour per layer]

---

## Repository structure

```
lab-ndr/
├── simulation/
│   ├── common.py                    packet builders — normal + standard attacks
│   ├── blind_attacks.py             blind test generators (disjoint parameters)
│   ├── generate_normal.py           normal traffic wrapper
│   ├── generate_attack_train.py     labelled attack PCAP generator
│   ├── inject_attack.py             manual injector (standard)
│   └── inject_blind_attack.py       manual injector (blind)
│
├── pipeline/
│   ├── build_features.py            Zeek logs → 152-feature JSONL
│   ├── train_baseline.py            HalfSpaceTrees training
│   ├── train_attack_classifier.py   CentroidAttackClassifier training
│   ├── score.py                     online scoring + learning control
│   ├── attack_classifier.py         classifier implementation
│   ├── feature_selection.py         baseline feature filter (99 of 152)
│   ├── anomaly_utils.py             expert signal heuristics
│   └── suricata_utils.py            Suricata alert classification
│
├── scripts/
│   ├── poc-train.ps1                full training pipeline
│   ├── validate-poc.ps1             standard validation matrix
│   ├── validate-blind.ps1           blind generalization test
│   ├── poc-live.ps1                 live processing loop
│   ├── poc-watcher.ps1              single PCAP processor
│   ├── demo-jefe.ps1                90-second demo
│   └── clean-repo.ps1               artifact cleanup
│
├── model/
│   ├── model.pkl                    trained HalfSpaceTrees baseline
│   ├── attack_classifier.pkl        trained CentroidAttackClassifier
│   ├── meta.json                    baseline metadata + thresholds
│   ├── attack_classifier_meta.json  classifier metrics + calibration
│   └── MODEL_CARD.md                model transparency document
│
├── suricata/etc/                    Suricata config + local rules
├── data/                            training PCAPs + live queue
├── output/                          live_scores.jsonl · learning_audit.jsonl
├── VALIDACION_POC.md
└── BLIND_TEST_RESULTS.md
```

---

## Limitations

No caveats for appearance — structural constraints worth knowing:

**Synthetic data, synthetic evaluation.** The 99.76% classifier accuracy is a measurement of the generator, not of the problem. The blind test is more honest, but it is still synthetic traffic.

**Data exfiltration is undertrained.** Twelve training examples. The blind test confirms it: this family is saved by heuristics, not by the classifier.

**Expert signal thresholds were tuned on the training generator.** They generalise to structurally similar variants (as the blind test shows), but they were not derived from literature or from real-world traffic analysis.

**No out-of-distribution evaluation.** The model has not been tested against CICIDS2017, UNSW-NB15, or any real captured traffic corpus.

**Trained on a three-host network.** The 0.95 anomaly threshold reflects that quiet environment. A real network would require recalibration.

---

## What comes next

In priority order:

**Evaluate against a public dataset** — CICIDS2017 or UNSW-NB15. First honest out-of-distribution measurement. Expected: accuracy drops, showing where the model needs work. That result is more publishable than 99.76%.

**Expand data exfiltration training** — From 12 to 200+ varied instances (sizes, chunk counts, endpoints). Should push recall from 75% to 95%+ and remove the dependency on the volume spike heuristic.

**Adversarial generator variants** — Slow port scans (1 connection/second), low-entropy DNS exfil (short labels), mimicry attacks that blend into normal traffic profiles. Quantify the evasion surface.

**Layer attribution report** — A script that runs each attack and reports which families Suricata alone, ML alone, and heuristics alone would catch. Makes the multi-layer value proposition concrete.

---

## Summary

EZEK13L detects what it was built to detect — and the blind test shows it learned behaviour, not parameters. The data exfiltration gap is real and documented. Everything else passed.

It is a lab. A well-built one.

---

*Suricata · Zeek · River · Scapy · Docker*
