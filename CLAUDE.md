# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

DDoS detection for a Software Defined Security course. A two-stage ML pipeline runs inside a Ryu SDN controller: an Autoencoder flags anomalous flows, then XGBoost classifies the attack type (Normal / DoS / DDoS). Detection is triggered by OpenFlow flow-stats polled every 2 seconds; when an attack is confirmed over `MIT_PERSISTENCE` consecutive polls, the controller installs a drop/rate-limit rule.

## Two separate Python environments

| Role | Python | Venv |
|------|--------|------|
| Detector (ML) | 3.11 (via `uv`) | `.venv` in repo root |
| Ryu controller | system (3.8) | system / separate venv |

These **must not share** a venv. The bridge is a TCP socket server on `127.0.0.1:9999`.

## Setup (detector venv, Python 3.11)

```bash
# Install uv if needed
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.bashrc

uv venv .venv --python 3.11
source .venv/bin/activate

# CPU-only PyTorch first (avoids 2 GB CUDA download)
uv pip install torch --index-url https://download.pytorch.org/whl/cpu
uv pip install -r requirements.txt
```

PPA deadsnakes on Ubuntu 20.04 focal does not provide Python 3.11. Use `uv` only.

## Key commands

```bash
# Train models from data/dataset.csv → models/
python -m src.train

# Run all three test suites (canonical detector cases + CSV evaluation + mitigation logic).
# CSV step uses data/test.csv if present (independent), else data/dataset.csv (sanity check).
# The mitigation step stubs ryu.* in sys.modules so detect_app can be imported from the 3.11 venv
# without needing Ryu installed — these tests verify _block_ip / _block_mac / _mitigate / _prune_blocks.
python test_bench.py

# Serve the detector over TCP (port 9999) — run in venv 3.11
python serve_detector.py

# Ryu: detection + mitigation (system Python, needs serve_detector.py running)
PYTHONPATH=. ryu-manager detect_app.py

# Capture the FULL labeled dataset from scratch (~25 min, needs Mininet + sudo).
# Drives Mininet through all 15 canonical scenarios and writes data/dataset.csv.
sudo python3 scripts/capture_full.py

# Capture a single class manually (uses the same per-flow extractor).
# CAPTURE_FILTER_IDLE=1 is REQUIRED for SYN-flood captures — otherwise the table
# fills with thousands of one-packet RST flows that swamp the discriminative signal.
CAPTURE_LABEL=normal  CAPTURE_CSV=data/dataset.csv CAPTURE_FILTER_IDLE=1 ryu-manager capture_app.py
CAPTURE_LABEL=dos     CAPTURE_CSV=data/dataset.csv CAPTURE_FILTER_IDLE=1 ryu-manager capture_app.py
CAPTURE_LABEL=ddos    CAPTURE_CSV=data/dataset.csv CAPTURE_FILTER_IDLE=1 ryu-manager capture_app.py
```

Three-terminal stack for live operation: (1) `python serve_detector.py`, (2) `ryu-manager detect_app.py`, (3) Mininet traffic.

## Code architecture

```
src/
├── live_features.py   ← canonical feature extraction (shared by capture + detect)
├── detector.py        ← Detector class: public API for both serve_detector and tests
└── train.py           ← trains from data/dataset.csv; saves all artefacts to models/

capture_app.py         ← Ryu app: captures labeled flow-stats → CSV
detect_app.py          ← Ryu app: detects attacks + installs mitigation rules
serve_detector.py      ← TCP socket server wrapping Detector.load()
test_bench.py          ← canonical test cases + CSV evaluation
```

### Feature names

`src/live_features.py` (`PER_FLOW + WINDOW = COLUMNS`) defines the **13** canonical features used at runtime and in `data/dataset.csv`:

- **Per-flow (7):** `src_port`, `dst_port`, `protocol`, `packets_per_sec`, `bytes_per_sec`, `avg_packet_size`, `flow_duration_sec`
- **Window (6):** `src_ip_entropy`, `dst_port_entropy`, `dst_ip_entropy`, `new_flows_per_sec`, `num_distinct_src_ips`, `num_distinct_dst_ips`

The two **destination-diversity** features (`dst_ip_entropy`, `num_distinct_dst_ips`) are what let the model distinguish "1 → N" multi-target attacks from "N → 1" classic DDoS, and benign mesh traffic (pingall) from multi-target floods (rate is the discriminator there).

The deployed architecture (Ryu app ↔ detector socket, mitigation flow, all ports/paths/knobs) lives in [docs/INTERFACE.md](docs/INTERFACE.md), and the model/scenarios writeup in [docs/Summary.md](docs/Summary.md).

### Training data

`python -m src.train` reads `data/dataset.csv` (captured by `scripts/capture_full.py` driving Mininet through 15 canonical scenarios). The original project proposal referenced the InSDN dataset, but it was discarded in favor of our own Mininet captures; the exploratory notebooks that used it have been removed. Labels in the CSV are lowercase (`normal`, `dos`, `ddos`); `train.py` maps them to `Normal`, `DoS`, `DDoS`. Duplicate rows are dropped (`DEDUP=True`).

The AE anomaly threshold is the percentile `AE_THRESHOLD_PERCENTILE` (default 99) of reconstruction error on the Normal validation split — tunable at the top of `src/train.py`. `Detector.predict(features, threshold=…)` also accepts a per-call override, which is the hook for a dynamic-threshold strategy in the Ryu app.

### Model artefacts (`models/`)

| File | Content |
|------|---------|
| `scaler.pkl` | StandardScaler fitted on Normal training flows |
| `autoencoder.pt` | Autoencoder state dict (architecture in `detector.py:Autoencoder`) |
| `xgb_classifier.pkl` | Multiclass XGBoost (production — Normal / DoS / DDoS) |
| `xgb_classifier_binary.pkl` | Binary XGBoost (comparison only — Normal / Attack) |
| `label_encoder.pkl` / `label_encoder_binary.pkl` | Corresponding LabelEncoders |
| `detector_meta.pkl` | Feature names, AE threshold (P99), architecture dims |

The Autoencoder architecture (`Linear 13→16→8→4→8→16→13`, ReLU, MSE) is defined in [src/detector.py:25-46](src/detector.py#L25-L46). If you change the architecture, models must be retrained.

### Detection flow

1. `live_features.window_features` + `per_flow_features` compute features from OFP stats.
2. `detect_app._ask_detector` sends each flow as a JSON line over TCP to `serve_detector`.
3. `Detector.predict` runs Autoencoder → if `score > threshold`, runs XGBoost → returns `DetectionResult`.
4. After `MIT_PERSISTENCE` (default 3) consecutive attack polls with confidence ≥ `MIT_MIN_CONF` (default 0.80), `detect_app._mitigate` installs an OpenFlow rule with `hard_timeout=MIT_TIMEOUT` (30 s, auto-expires):
   - **DoS** → drop by source IP (`OFPMatch(eth_type=IPv4, ipv4_src=<atacante>)`)
   - **DDoS** → drop by source **MAC** (`OFPMatch(eth_src=<MAC>)`). The flow stats only carry IPs, so `detect_app` resolves IP→MAC via `self.ip_to_mac`, a map populated on every `packet_in` (`self.ip_to_mac[ip.src] = eth.src`). Blocking at L2 catches `--rand-source` attackers that spoof IPs but not the physical MAC. Rationale in [docs/Summary.md § Acciones de mitigación](docs/Summary.md#acciones-de-mitigación).

### Grafana / InfluxDB

`detect_app.py` writes to InfluxDB (db `SDS`, default port 8086) three measurements: `detection` (per-poll timeseries), `attack_event` (one per attack episode start), `blocks` (mitigation lifecycle — `tags={type, target}`, `fields={active, expires}`; for DDoS `target` is now a MAC address, for DoS an IP). The full dashboard (11 panels) can be imported as-is from [grafana/sds_dashboard.json](grafana/sds_dashboard.json); per-query details in [docs/grafana.md](docs/grafana.md).
