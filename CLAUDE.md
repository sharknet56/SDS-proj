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

# Run canonical test cases + CSV evaluation
# Uses data/test.csv if it exists (independent test set), else data/dataset.csv (sanity check on training data).
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

# Jupyter notebooks (EDA and model exploration only)
jupyter lab notebooks/
```

Three-terminal stack for live operation: (1) `python serve_detector.py`, (2) `ryu-manager detect_app.py`, (3) Mininet traffic.

## Code architecture

```
src/
├── live_features.py   ← canonical feature extraction (shared by capture + detect)
├── detector.py        ← Detector class: public API for both serve_detector and tests
├── train.py           ← trains from data/dataset.csv; saves all artefacts to models/
└── features.py        ← InSDN-specific mappings (used only in exploratory notebooks)

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

`src/features.py` contains InSDN-to-OpenFlow mappings with different names (e.g. `pkts_per_sec`, `avg_pkt_size`, `flow_age_sec`) — these are used only in the exploratory notebooks, **not** at training/inference time. The example in `README.md` still uses the InSDN names and is stale — trust `src/live_features.py:COLUMNS`. The deployed architecture (Ryu app ↔ detector socket, mitigation flow, all ports/paths/knobs) lives in [docs/INTERFACE.md](docs/INTERFACE.md), and the model/scenarios writeup in [docs/Summary.md](docs/Summary.md).

A few docstrings still say "11 features" (e.g. [detect_app.py:3](detect_app.py#L3)). They are stale — the count is 13.

### Training data

`python -m src.train` reads `data/dataset.csv` (captured by `scripts/capture_full.py` driving Mininet through 15 canonical scenarios), **not** InSDN. InSDN is used only in `notebooks/01–04` for exploratory work. Labels in the CSV are lowercase (`normal`, `dos`, `ddos`); `train.py` maps them to `Normal`, `DoS`, `DDoS`. Duplicate rows are dropped (`DEDUP=True`).

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

`models/iforest.pkl` may also be present from earlier experiments — it is not loaded by `Detector.load` or any current code path. Safe to ignore.

The Autoencoder architecture (`Linear 13→16→8→4→8→16→13`, ReLU, MSE) is defined in [src/detector.py:25-46](src/detector.py#L25-L46) and duplicated in `notebooks/03_anomaly_detector.ipynb`. If you change the architecture, both must stay in sync and models must be retrained.

### Detection flow

1. `live_features.window_features` + `per_flow_features` compute features from OFP stats.
2. `detect_app._ask_detector` sends each flow as a JSON line over TCP to `serve_detector`.
3. `Detector.predict` runs Autoencoder → if `score > threshold`, runs XGBoost → returns `DetectionResult`.
4. After `MIT_PERSISTENCE` (default 3) consecutive attack polls with confidence ≥ `MIT_MIN_CONF` (default 0.80), `detect_app._mitigate` installs an OpenFlow rule:
   - **DoS** → drop by source IP
   - **DDoS** → rate-limit by destination IP:port via OVS meter (falls back to drop if meters unavailable)

### Grafana / InfluxDB

`detect_app.py` writes to InfluxDB (db `SDS`, default port 8086) three measurements: `detection` (per-poll timeseries), `attack_event` (one per attack episode start), `blocks` (mitigation lifecycle). See `grafana.md` for dashboard setup.
