# SDS-proj — Detección de DDoS en SDN

Proyecto de la asignatura **Software Defined Security**. Detección de ataques DDoS sobre una red SDN (Mininet + Ryu) mediante un modelo de ML que aprende el comportamiento normal de la red y aplica un umbral de anomalía aprendido en entrenamiento.

## División del equipo

- **Subgrupo A (este repo)** — Modelo de detección.
- **Subgrupo B** — Topología SDN (Mininet) y bloqueo (instalación de reglas OpenFlow).

Documentación del sistema desplegado:
- [`docs/INTERFACE.md`](docs/INTERFACE.md) — arquitectura desplegada, cómo se comunican Ryu ↔ detector ↔ InfluxDB.
- [`docs/Summary.md`](docs/Summary.md) — qué hace el modelo, las 13 features, qué detecta y qué no.
- [`docs/setup.md`](docs/setup.md) — instalación paso a paso.
- [`docs/grafana.md`](docs/grafana.md) — paneles de Grafana sobre las métricas que escribe `detect_app.py`.
- [`CLAUDE.md`](CLAUDE.md) — guía de orientación para futuras sesiones de Claude Code.

## Enfoque

Pipeline híbrido en dos etapas:

1. **Detector de anomalías no supervisado** (Autoencoder) entrenado solo con tráfico benigno. El umbral se fija en entrenamiento como el **percentil 99 del error de reconstrucción** sobre un split de validación de tráfico normal — es decir, "el 1% de los flujos legítimos ya da un error de este nivel; por encima lo consideramos sospechoso". El proceso, paso a paso:
   1. Se separa el 70/30 de los flujos `Normal` en `train` / `val`.
   2. El AE se entrena solo con el 70%.
   3. Se calcula el error de reconstrucción sobre el 30% (datos que el AE no ha visto).
   4. El umbral es `np.percentile(errores_val, 99)`. Se guarda en `models/detector_meta.pkl` y lo carga `Detector.load()`.

   El umbral es **estático** porque en este escenario (Mininet, topología fija, tráfico reproducible) no hay deriva de distribución entre entreno y producción. Un umbral dinámico (percentil rolling sobre ventana deslizante) tendría sentido en un despliegue real con drift; aquí sería resolver un problema que no tenemos.
2. **Clasificador supervisado** (XGBoost multiclase: Normal / DoS / DDoS) que confirma si la anomalía es ataque y clasifica el tipo.

## Dataset

Capturado por nosotros con [`scripts/capture_full.py`](scripts/capture_full.py), que lanza Mininet a través de 15 escenarios canónicos (3 Normal + 8 DoS + 4 DDoS) y vuelca las features a `data/dataset.csv`. La propuesta inicial usaba el dataset público InSDN, pero fue descartado porque el skew entre sus features y las derivables de OpenFlow live era demasiado grande — al capturar nosotros mismos garantizamos que el modelo offline ve exactamente lo mismo que el detector en vivo.

## Estructura del repo

```
SDS-proj/
├── data/
│   └── dataset.csv        # capturado por scripts/capture_full.py
├── src/
│   ├── live_features.py   # extracción de las 13 features (capture + detect)
│   ├── detector.py        # Detector.load() / predict() — API del modelo
│   └── train.py           # entrena AE + XGBoost desde data/dataset.csv
├── models/                # artefactos entrenados (no versionados)
├── scripts/
│   └── capture_full.py    # captura el dataset desde cero
├── capture_app.py         # Ryu app: captura labeled flow-stats -> CSV
├── detect_app.py          # Ryu app: detección + mitigación en vivo
├── serve_detector.py      # servidor TCP que envuelve Detector.load()
├── test_bench.py          # banco de pruebas
├── docs/                  # INTERFACE.md, Summary.md, setup.md, grafana.md
├── grafana/               # dashboard de Grafana exportado
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Para los detalles operativos (versiones de Python, captura del dataset, despliegue de Ryu/InfluxDB/Grafana) ver [`docs/setup.md`](docs/setup.md).

## Uso

Entrenar el modelo desde el CSV capturado:

```bash
python -m src.train
```

Usarlo desde la Ryu app:

```python
from src.detector import Detector

detector = Detector.load("models/")
result = detector.predict(features_dict)
# DetectionResult(is_anomaly=True, attack_type='DoS', confidence=0.97, anomaly_score=12.7)
```
