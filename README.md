# EZEK13L

**Network Detection & Response — Local Lab**

Multi-layer attack detection on synthetic network traffic. Combines Suricata, Zeek, unsupervised anomaly detection, and a supervised attack classifier. Runs entirely in Docker.

> Proof-of-concept. Synthetic traffic, virtual hosts, no production claims.

[IMAGE: dark terminal screenshot showing the blind test — five PASS lines in sequence, monospace font on black background]

---

## Table of contents

- [What it is](#what-it-is)
- [How it looks](#how-it-looks)
- [Installation](#installation)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Blind Generalization Test](#blind-generalization-test)
- [Limitations](#limitations)
- [What comes next](#what-comes-next)

---

## What it is

A local NDR lab that detects five attack families across four independent detection layers:

| Layer | Technology | What it catches |
|---|---|---|
| 1 | HalfSpaceTrees (unsupervised) | Statistical anomalies vs. normal baseline |
| 2 | CentroidAttackClassifier (supervised) | Known attack families by behaviour profile |
| 3 | Expert signals (heuristics) | Scan pressure, DNS entropy, HTTP shape, volume spikes |
| 4 | Suricata (signatures) | Known payloads via community ruleset |

When one layer misses, another covers. The blind test at the end of this document shows that in practice.

**Attack families detected:** Port Scan · DNS Exfiltration · Brute Force HTTP · SQL Injection · Data Exfiltration

---

## How it looks

[IMAGE: side-by-side of VALIDACION_POC.md and BLIND_TEST_RESULTS.md tables — same 5 attacks, both sets PASS]

Standard validation output (`VALIDACION_POC.md`):

```
[PASS] Control benigno    raw=0.920  detections=0   layers=—
[PASS] Port Scan          raw=0.851  detections=46  layers=ML, Expert, Suricata
[PASS] DNS Exfiltration   raw=0.800  detections=23  layers=ML, Expert
[PASS] Brute Force HTTP   raw=0.836  detections=25  layers=ML, Suricata
[PASS] SQL Injection      raw=0.796  detections=7   layers=ML, Expert, Suricata
[FAIL] Data Exfiltration  raw=0.752  detections=0   layers=Expert
```

Blind test output — different IPs, domains, and payloads, model not retrained (`BLIND_TEST_RESULTS.md`):

```
[PASS] Control benigno       raw=0.920  detections=0   layers=—
[PASS] Port Scan (blind)     raw=0.851  detections=16  layers=ML, Expert, Suricata
[PASS] DNS Exfiltration      raw=0.794  detections=19  layers=ML, Expert
[PASS] Brute Force HTTP      raw=0.852  detections=17  layers=ML, Suricata
[PASS] SQL Injection         raw=0.818  detections=8   layers=ML, Expert, Suricata
[PASS] Data Exfiltration     raw=0.931  detections=0   layers=Expert

Blind result: 5/5 attacks detected
```

[IMAGE: actual terminal screenshot of validate-blind.ps1 running — full output visible]

---

## Installation

**Requirements:** Docker Desktop (Windows, `docker-users` group configured) · PowerShell 5.1+

```powershell
git clone https://github.com/JaviCKP/EZEK13L.git
cd EZEK13L
.\scripts\poc-train.ps1
```

`poc-train.ps1` generates synthetic traffic, processes it through Zeek, extracts features, and trains both models. Output goes to `model/`.

---

## Usage

**Run the full validation matrix**
```powershell
.\scripts\validate-poc.ps1
```

**Run the blind generalization test** (different IPs, domains, payloads — no retraining)
```powershell
.\scripts\validate-blind.ps1
```

**Quick 90-second demo**
```powershell
.\scripts\demo-jefe.ps1
```

**Inject an attack manually**
```powershell
docker compose run --rm py python simulation/inject_attack.py        # standard
docker compose run --rm py python simulation/inject_blind_attack.py  # blind variants
```

**Strict ML-only validation** (Suricata and heuristics don't count as PASS)
```powershell
.\scripts\validate-poc.ps1 -RequireMl
```

---

## How it works

### Pipeline

```
  TRAFFIC GENERATION
  simulation/generate_normal.py     benign: admin · dev · RRHH hosts
  simulation/inject_attack.py       5 attack families · 2 generators

          │ .pcap
          ▼

  PROCESSING
  Zeek  →  conn.log · http.log · dns.log · tls.log
  Suricata  →  eve.json (alerts)

          │ 152 features / flow
          ▼

  SCORING  (pipeline/score.py)
  ┌─────────────────────────────────────────┐
  │  Layer 1 — HalfSpaceTrees baseline      │  raw_score vs threshold 0.95
  ├─────────────────────────────────────────┤
  │  Layer 2 — CentroidAttackClassifier     │  6 classes · confidence ≥ 0.45
  ├─────────────────────────────────────────┤
  │  Layer 3 — Expert signals               │  behavioral_boost + factors
  ├─────────────────────────────────────────┤
  │  Layer 4 — Suricata correlation         │  cross-reference by IP + flow
  └─────────────────────────────────────────┘

          │
          ▼
  output/live_scores.jsonl   ·   VALIDACION_POC.md   ·   BLIND_TEST_RESULTS.md
```

### Network topology

```
192.168.50.0/24
  ├── .10   pc_admin    web browsing, report downloads
  ├── .11   pc_dev      API calls, TLS, DNS
  ├── .12   pc_rrhh     file shares, uploads
  ├── .1    srv_web     internal web/API server (attack target)
  └── .2    srv_dns     DNS resolver

10.0.0.99    attacker        standard attacks
172.16.0.50  blind_attacker  blind test (never seen during training)
```

### Models

**Baseline — HalfSpaceTrees** (unsupervised)
Trained on 8 979 normal traffic events. Uses ratio features (`error_ratio_60s`) instead of raw counters to avoid environment-specific overfitting. Threshold: 0.95 (99.9th percentile of holdout). Online learning is blocked on any flow that scores above 0.75, triggers Suricata, or is classified as an attack — anti-poisoning by design.

**Classifier — CentroidAttackClassifier** (supervised)
Centroid k-NN with softmax temperature scaling (T=0.35). Trained on 2 460 labelled synthetic events.

| Class | Train samples | Test F1 |
|---|---:|---:|
| normal | 1 800 | 0.998 |
| port_scan | 643 | 1.000 |
| brute_force_http | 421 | 1.000 |
| dns_exfiltration | 286 | 0.993 |
| sql_injection | 117 | 1.000 |
| data_exfiltration | 12 | 0.857 |

---

## Blind Generalization Test

The standard validation trains and tests on the same generator. To check whether the model learned attack *behaviour* or just attack *parameters*, a second generator was built with entirely different characteristics — and the model was not retrained.

| Parameter | Standard | Blind |
|---|---|---|
| Attacker IP | `10.0.0.99` | `172.16.0.50` |
| Port scan | Ports 20–99, sequential | Windows service ports: 135, 445, 1433, 3389… |
| DNS C2 domain | `*.evil-c2.com` | `*.cdn-update.net` |
| Brute force endpoint | `POST /login` | `POST /api/auth/token` |
| SQL payloads | UNION · OR 1=1 · sleep() | WAITFOR · xp_cmdshell · CAST · DROP TABLE |
| Data exfil | Single POST 650 KB–3 MB | 3–6 chunks of 100–400 KB |

Result: **5/5 families detected.** Each through a different layer combination — which is the point of the multi-layer design.

The one honest weak spot: Data Exfiltration is caught by the volume spike heuristic, not by the classifier. The classifier has 12 training examples for that class. It's documented, not hidden.

---

## Limitations

- **Synthetic data throughout.** The 99.76% classifier accuracy measures the generator, not the real problem. The blind test is more honest, but still synthetic.
- **Data exfiltration is undertrained.** 12 examples. Needs 200+.
- **No evaluation against real traffic.** Not tested against CICIDS2017, UNSW-NB15, or any captured corpus.
- **Three-host baseline.** The 0.95 threshold reflects a quiet lab network. A real network needs recalibration.

---

## What comes next

**Evaluate against CICIDS2017 or UNSW-NB15** — first honest out-of-distribution measurement.

**Expand data exfiltration training** — 12 → 200+ varied instances to remove the heuristic dependency.

**Adversarial variants** — slow scans, low-entropy DNS exfil, traffic mimicry. Quantify the evasion surface.

**Layer attribution report** — measure what each layer catches independently to make the multi-layer value concrete.

---

*Suricata · Zeek · River · Scapy · Docker*
