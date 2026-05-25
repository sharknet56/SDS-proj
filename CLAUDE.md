# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

DDoS detector for an SDN environment. Subgroup A (this repo) trains an ML model from OpenFlow flow-stats and exposes a detector; subgroup B runs the Ryu controller / Mininet topology and consumes alerts (contract in [docs/INTERFACE.md](docs/INTERFACE.md)). This repo also contains the Ryu apps used to capture the training dataset and to run live detection + mitigation.

## Environments (two separate venvs)

This repo deliberately uses **two distinct Python environments** that must not be mixed:

- **Detector venv (Python 3.11, via `uv`)** — runs `src/`, `serve_detector.py`, `test_bench.py`, notebooks, training. Modern PyTorch / pandas / xgboost. Setup steps in [setup.md](setup.md).
- **Ryu env (system Python, older)** — runs `capture_app.py`, `detect_app.py`, `ryu_min_monitor.py` via `ryu-manager`. Ryu is picky about Python versions; keep it separate.

The Ryu apps talk to the detector over a TCP socket (127.0.0.1:9999), so they can run in different interpreters.

## Common commands

Activate the detector venv first (`source .venv/bin/activate`) for everything except `ryu-manager`.

```bash
# Train (writes all artefacts into models/)
python -m src.train

# Start the detector server (listens on 127.0.0.1:9999)
python serve_detector.py

# Regression + dataset evaluation
python test_bench.py

# Capture a class of traffic to data/dataset.csv (run once per class)
CAPTURE_LABEL=normal CAPTURE_CSV=data/dataset.csv ryu-manager capture_app.py
CAPTURE_LABEL=dos    CAPTURE_CSV=data/dataset.csv ryu-manager capture_app.py
CAPTURE_LABEL=ddos   CAPTURE_CSV=data/dataset.csv ryu-manager capture_app.py

# Live detection + mitigation (3 terminals; see touse.txt)
#   T1: python serve_detector.py
#   T2: PYTHONPATH=. ryu-manager detect_app.py
#   T3: sudo mn --topo tree,depth=2,fanout=2 --switch ovsk,protocols=OpenFlow13 \
#               --controller=remote,ip=127.0.0.1,port=6633

# Notebooks
jupyter lab notebooks/
```

There is no test framework: [test_bench.py](test_bench.py) is a hand-rolled script with canonical cases (PASS/FAIL) and a CSV-wide evaluation. Add new regression cases to its `CASES` list rather than introducing pytest.

## Architecture

### Training pipeline (`src/train.py`)

Reads [data/dataset.csv](data/) (11 features + `label` ∈ {normal, dos, ddos}, normalized via `LABEL_MAP`) and produces three models written to `models/`:

1. **Autoencoder** (`src/detector.py:Autoencoder`, 11 → 16 → 8 → 4 → 8 → 16 → 11) trained only on `Normal` rows. Anomaly threshold = P99 of reconstruction error on a held-out Normal split.
2. **XGBoost multiclass** {Normal, DoS, DDoS} — **the production classifier** (`xgb_classifier.pkl`). DoS vs DDoS distinction relies on `num_distinct_src_ips` / `src_ip_entropy`.
3. **XGBoost binary** {Normal, Attack} — kept only for comparison reporting; not used at inference.

Persisted artefacts (all loaded by `Detector.load`): `scaler.pkl`, `autoencoder.pt`, `xgb_classifier.pkl`, `label_encoder.pkl`, `detector_meta.pkl` (contains `features`, `ae_thr_p99`, `ae_arch`). The binary variant (`xgb_classifier_binary.pkl`, `label_encoder_binary.pkl`) is written but not consumed.

### Inference (`src/detector.py:Detector`)

Two-stage pipeline. `Detector.predict(features)`:

1. Computes AE reconstruction error, compares to threshold (default P99, override per-call).
2. For flows above threshold, runs XGBoost multiclass → returns `attack_type` and `confidence`. Normal flows skip the classifier (CPU win).
3. `is_anomaly` is derived as `attack_type != "Normal"`. The literal string `"Normal"` is load-bearing — see [src/train.py:52](src/train.py#L52) (`LABEL_MAP`) and [src/detector.py:87](src/detector.py#L87).

Input may be a `dict` (single flow) or `DataFrame` (batch). Feature names and order come from `detector_meta.pkl["features"]`; missing columns raise.

### Feature contract (single source of truth)

[src/live_features.py](src/live_features.py) defines `PER_FLOW` + `WINDOW` features and is **shared by capture and live detection** to prevent train/serve skew. If you change features, you must:

- Update both [src/live_features.py](src/live_features.py) and the training CSV schema.
- Retrain (`python -m src.train`) so `detector_meta.pkl` reflects the new feature list.
- Update [docs/INTERFACE.md](docs/INTERFACE.md) (the contract with subgroup B).

[src/features.py](src/features.py) is the *offline* equivalent (mapping for the academic InSDN dataset reference); it is not used by the live path. The "deployable" model deliberately avoids InSDN's IAT / TCP-flag features because those require packet inspection and aren't available from OpenFlow stats.

### Ryu apps

- **[capture_app.py](capture_app.py)** — L2 switch + per-poll flow-stats sampler that writes a CSV row per flow with the chosen `CAPTURE_LABEL`. Installs flows by `(src_ip, dst_ip, ip_proto, l4_dst)` so that one fake source IP under `--rand-source` = one flow → DDoS diversity is visible in stats. Important: when generating DDoS traffic, **acotar** the attack (`--faster` + `-c`, never `--flood`) or the flow table explodes.
- **[detect_app.py](detect_app.py)** — Live detection. Same feature extraction, sends each poll's flows to the detector over TCP, applies **mitigation** with three safeguards: persistence (`MIT_PERSISTENCE` consecutive bad polls), confidence (`MIT_MIN_CONF`), and expiry (`hard_timeout=MIT_TIMEOUT`). DoS → drop source IP. DDoS → rate-limit victim:port via OFP meter, with a drop-rule fallback (`USE_METER = False`) if the OVS build doesn't support meters reliably.
- **[ryu_min_monitor.py](ryu_min_monitor.py)** — minimal monitor variant, no mitigation; useful for debugging the socket path.

`POLL = 2` seconds across all apps; flow-stats deltas are divided by this interval to get rates.

### Detector ↔ Ryu protocol

Newline-delimited JSON over TCP `127.0.0.1:9999`. One JSON object (features) per line → one JSON object (`DetectionResult.to_dict()`) per line. `serve_detector.py` is a tiny `socketserver.ThreadingTCPServer` wrapper; if you change the wire format, update [detect_app.py](detect_app.py) and [ryu_min_monitor.py](ryu_min_monitor.py) too.

## Conventions

- Code comments and docstrings are in Spanish; preserve the language when editing.
- `data/raw/`, `data/processed/`, `models/*` are git-ignored; they are regenerable.
- Kaggle credentials live in `.env` (also git-ignored). The InSDN download path is only used by exploratory notebooks; the production training reads the locally captured `data/dataset.csv`.
- `requirements.txt` has no pins; if a fresh install breaks training, `setup.md` records a known-good set of versions (numpy 2.4, pandas 3.0, torch 2.12 cpu, scikit-learn 1.8, xgboost 3.2).
