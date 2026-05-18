# Summary — Detector DDoS

Para que entiendas en 5 minutos lo que hemos montado y puedas levantar el proyecto en tu máquina.

## Qué hace el detector

Un pipeline en **dos etapas** que toma estadísticas de flow desde OpenFlow y dice si hay ataque y de qué tipo:

```
flow stats (OpenFlow)
        │
        ▼
   Scaler (StandardScaler)
        │
        ▼
   Autoencoder  ─── error de reconstrucción
        │              │
        │       ¿score > threshold?
        │              │
   ┌────┴───┐    sí ───┴─── no
   ▼        ▼                 ▼
XGBoost  decide Normal     Normal (sin gastar XGB)
   │
   ▼
attack_type ∈ {DDoS, DoS, Probe, BFA, Normal}
```

- El **Autoencoder** se entrena solo con tráfico Normal → si un flow no se parece a lo normal, score alto.
- El **threshold** es dinámico: P99 de la validación Normal por defecto, pero la Ryu app puede inyectar uno calculado sobre una ventana deslizante.
- El **XGBoost** clasifica el tipo de ataque y también puede rechazar falsos positivos del AE diciendo "Normal".

## Por qué este diseño

- Solo usamos **7 features derivables de OpenFlow** (`src_port`, `dst_port`, `protocol`, `pkts_per_sec`, `bytes_per_sec`, `avg_pkt_size`, `flow_age_sec`). Las otras 77 de CICFlowMeter requieren inspección de paquetes y no las tendríamos en vivo.
- Con esas 7 features el F1 macro ya está en ~0.995 sobre InSDN — equivalente al modelo "full" con todas las features. Eso confirma que limitarnos a OpenFlow no nos cuesta rendimiento.
- DDoS se detecta perfectamente (lo que vamos a generar en Mininet). Probe/BFA se pierden a P99 — comentado en la memoria como decisión consciente.

## Dataset

**InSDN 2020** desde Kaggle (`muhammadumarjavaid/insdn-dataset-2020`):
- 205.167 flows, 84 features + Label.
- Clases: DDoS 36% / Normal 33% / Probe 30% / DoS 0.6% / BFA 0.14% / U2R 0.008% (descartamos U2R, son 17 muestras).
- Ya viene limpio (0 NaN, 0 Inf).

## Estructura del repo

```
SDS-proj/
├── data/raw/                  # vacío, kagglehub cachea en ~/.cache/kagglehub
├── notebooks/
│   ├── 01_eda.ipynb           # exploración inicial
│   ├── 02_baseline_rf.ipynb   # Random Forest, comparativa full vs deployable
│   ├── 03_anomaly_detector.ipynb   # AE + Isolation Forest + threshold
│   └── 04_classifier.ipynb    # XGBoost + pipeline completo
├── src/
│   ├── data.py                # get_insdn_path() — descarga vía kagglehub
│   ├── features.py            # constantes (INSDN_TO_OPENFLOW, etc.)
│   ├── detector.py            # ← clase Detector que importa la Ryu app
│   └── train.py               # pipeline end-to-end (regenera todo en 1 min)
├── models/                    # artefactos entrenados (no versionados)
├── docs/INTERFACE.md          # contrato con el subgrupo de topología
└── requirements.txt
```

## Cómo levantarlo en tu máquina

1. **Clonar el repo** y meter tu `.env` en la raíz:
   ```
   KAGGLE_API_TOKEN=tu_token_de_kaggle
   ```
   (Sacas el token en https://www.kaggle.com/settings → *Create new token*. Si ya tenías `KAGGLE_USERNAME` y `KAGGLE_KEY` por separado, también vale.)

2. **Entorno virtual** + dependencias:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Generar los modelos** (descarga InSDN la primera vez):
   ```bash
   python -m src.train
   ```
   Tarda ~1-2 min en CPU. Te deja todo en `models/`.

4. **Probarlo**:
   ```python
   from src.detector import Detector
   det = Detector.load("models/")
   det.predict({
       "src_port": 51234, "dst_port": 443, "protocol": 6,
       "pkts_per_sec": 5.0, "bytes_per_sec": 4000.0,
       "avg_pkt_size": 800.0, "flow_age_sec": 2.5,
   })
   # → DetectionResult(is_anomaly=False, attack_type='Normal', ...)
   ```

5. Si quieres explorar los notebooks: `jupyter lab notebooks/`.

## API del Detector (lo que verá la Ryu app)

```python
det = Detector.load("models/")

# Una predicción
det.predict(flow_dict)                       # usa threshold estático
det.predict(flow_dict, threshold=dyn_thr)    # umbral dinámico inyectado

# Batch (más eficiente)
det.predict(df_flows)

# Acceso
det.feature_names        # ['src_port', 'dst_port', ...]
det.default_threshold    # 0.25478 (P99 de val Normal)
```

`DetectionResult` tiene: `is_anomaly`, `attack_type`, `confidence`, `anomaly_score`. Hay `.to_dict()` para serializar al evento JSON que mandaremos al subgrupo de bloqueo (ver `docs/INTERFACE.md`).

## Qué falta

- Acordar el contrato definitivo con el subgrupo de topología (intervalo de polling, granularidad de la alerta, dónde se calculan las features agregadas de ventana). Borrador en `docs/INTERFACE.md`.
- Validación end-to-end en Mininet con `hping3` + `iperf3` cuando tengan la topología.
- Para la memoria: experimento "leave-one-attack-out" y comparativa umbral fijo vs dinámico — pendientes, no urgentes.

## Si algo no te cuadra

- Si `python -m src.train` falla en la descarga → revisa que el `.env` esté en la raíz del repo y que el token sea válido.
- Si el F1 que sale es <0.99 → revisa que estés usando los 7 features deployable, no los originales.
- Cualquier duda sobre el pipeline, los notebooks están comentados en castellano y se ejecutan en orden 01 → 04.
