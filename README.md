# SDS-proj — Detección de DDoS en SDN

Proyecto de la asignatura **Software Defined Security**. Detección de ataques DDoS sobre una red SDN (Mininet + Ryu) mediante un modelo de ML que aprende el comportamiento normal de la red y define un umbral dinámico de anomalía.

## División del equipo

- **Subgrupo A (este repo)** — Modelo de detección.
- **Subgrupo B** — Topología SDN (Mininet) y bloqueo (instalación de reglas OpenFlow).

El contrato entre ambos subgrupos está documentado en [`docs/INTERFACE.md`](docs/INTERFACE.md).

## Enfoque

Pipeline híbrido en dos etapas:

1. **Detector de anomalías no supervisado** (Autoencoder / Isolation Forest) entrenado solo con tráfico benigno. Define el umbral de forma dinámica como percentil del error de reconstrucción sobre una ventana deslizante.
2. **Clasificador supervisado** (XGBoost) que confirma si la anomalía es DDoS y clasifica el tipo de ataque.

## Dataset

[InSDN (2020)](https://www.kaggle.com/datasets/muhammadumarjavaid/insdn-dataset-2020) — flows capturados en una topología SDN con Ryu y OvS, etiquetados.

## Estructura del repo

```
SDS-proj/
├── data/
│   ├── raw/              # InSDN sin tocar (no versionado)
│   └── processed/        # Tras limpieza y feature engineering
├── notebooks/
│   ├── 01_eda.ipynb              # Exploración del dataset
│   ├── 02_baseline_rf.ipynb      # Random Forest como techo de referencia
│   ├── 03_anomaly_detector.ipynb # Autoencoder / Isolation Forest
│   └── 04_classifier.ipynb       # XGBoost
├── src/
│   ├── features.py       # Feature engineering reutilizable
│   ├── detector.py       # Clase final con load() / predict()
│   └── train.py          # Script de entrenamiento reproducible
├── models/               # Modelos entrenados (.pkl / .pt)
├── docs/
│   └── INTERFACE.md      # Contrato con el subgrupo de topología
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Descargar InSDN

Usamos `kagglehub` (versión ≥ 0.4.1). Crear un API token en https://www.kaggle.com/settings → *Create new token* y guardarlo en un `.env` en la raíz del repo (ya está en `.gitignore`):

```bash
# .env
KAGGLE_API_TOKEN=tu_api_token
```

Alternativamente, el formato clásico `KAGGLE_USERNAME` + `KAGGLE_KEY` también funciona.

Después, desde un notebook o script:

```python
from src.data import get_insdn_path
path = get_insdn_path()      # descarga si hace falta, cachea en ~/.cache/kagglehub/
print(path)
```

## Uso

Para explorar: abrir los notebooks en orden.

Para entrenar el modelo final:

```bash
python -m src.train
```

Para usarlo desde la Ryu app del subgrupo B:

```python
from src.detector import Detector

detector = Detector.load("models/")
result = detector.predict(features_dict)
# {"is_anomaly": True, "attack_type": "syn_flood", "confidence": 0.93}
```
