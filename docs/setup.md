# Setup — Detector DDoS

Guía para levantar el detector desde cero en una máquina nueva (Ubuntu 20.04 / VM).
Esta es la ruta que **realmente** ha funcionado, no la teórica del README.

> **Resumen de 10 segundos:** el sistema trae Python 3.8, que ya no vale.
> Usamos `uv` para tener Python 3.11 sin pelearnos con apt, y de ahí todo va seguido.
>
> El detector (`.venv` Python 3.11) y el controlador Ryu (Python sistema) viven en
> **entornos separados** y se hablan por un socket TCP. Cómo encajan las piezas,
> en [`INTERFACE.md`](INTERFACE.md).

---

## 0. Requisitos previos

- Ubuntu 20.04 (focal) o similar. CPU, sin GPU (entrenamos en CPU).
- ~10 GB de disco libres (sobra con 60). El grueso es PyTorch (~200 MB el wheel, ~3-4 GB el entorno).
- (Opcional, solo para los notebooks exploratorios `01_…` a `04_…`): cuenta de
  Kaggle para descargar el dataset InSDN. **El entrenamiento productivo NO usa
  InSDN** — usa `data/dataset.csv` que capturamos nosotros en Mininet.
- Para operación en vivo / capturar dataset desde cero: Mininet + Ryu instalados
  en el Python del sistema (ya vienen en la VM del Lab 4).

---

## 1. Python 3.11 vía `uv` (recomendado)

El Python del sistema es el 3.8 y PyTorch / pandas modernos requieren 3.9+.
Intentar instalar `python3.11` con `apt` + PPA deadsnakes **no funcionó** en focal
(el PPA se añade pero no ofrece el paquete). La vía limpia es `uv`, que se descarga
el intérprete él solo:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc          # recarga el PATH; si no, abre una terminal nueva
uv --version              # debe responder con un número de versión
```

---

## 2. Clonar el repo y crear el entorno

```bash
git clone https://github.com/sharknet56/SDS-proj.git
cd SDS-proj

uv venv .venv --python 3.11    # uv descarga CPython 3.11 si no lo tienes
source .venv/bin/activate
python --version               # debe decir 3.11.x  (NO 3.8)
```

A partir de aquí el prompt debe empezar por `(.venv)`.

---

## 3. Instalar dependencias

PyTorch primero, forzando la build **CPU** (evita bajar ~2 GB de librerías CUDA inútiles):

```bash
uv pip install torch --index-url https://download.pytorch.org/whl/cpu
uv pip install -r requirements.txt
```

> `uv pip` funciona dentro del venv igual que `pip`, pero mucho más rápido.

---

## 4. (Opcional) Token de Kaggle para los notebooks exploratorios

**Solo necesario si vas a abrir los notebooks `01_eda` … `04_classifier`**, que
sí usan InSDN. El entrenamiento productivo (paso 6) **no** lo necesita.

Crea un token en <https://www.kaggle.com/settings> → *Create new token* y mételo
en un fichero `.env` **en la raíz del repo** (ya está en `.gitignore`):

```bash
echo "KAGGLE_API_TOKEN=tu_token_aqui" > .env
```

Alternativa clásica: `KAGGLE_USERNAME=...` y `KAGGLE_KEY=...` en el mismo `.env`.

---

## 5. Conseguir `data/dataset.csv`

El detector se entrena con un CSV capturado por nosotros en Mininet (no con InSDN).
Dos opciones:

**Opción A — usar el dataset que ya está en el repo / VM del equipo.**
Comprueba que existe:

```bash
ls -lh data/dataset.csv     # debe pesar varios MB y traer la columna label
```

Si está, salta al paso 6.

**Opción B — capturarlo desde cero** (~25 min, necesita Mininet + sudo + Ryu del
sistema). Es un script que conduce Mininet por 15 escenarios canónicos:

```bash
sudo python3 scripts/capture_full.py
```

Sobre los escenarios y por qué son los que son, ver [`Summary.md` § Dataset](Summary.md#dataset).
Si solo quieres capturar una clase manualmente (útil para depurar), está
documentado en `CLAUDE.md` y en la cabecera de `capture_app.py`.

---

## 6. Entrenar

```bash
python -m src.train
```

- Lee `data/dataset.csv` (capturado en el paso anterior). **No descarga InSDN.**
- Tarda ~1 min en CPU.
- Al acabar deja los artefactos en `models/` (scaler, autoencoder, XGBoost,
  label encoder, metadatos) e imprime accuracy y F1 macro (debería rondar 0.99).

---

## 7. Probar el detector (sin Mininet)

Las features que espera el detector son las 13 canónicas de `src/live_features.py:COLUMNS`
— **no** los nombres "estilo InSDN" (`pkts_per_sec`, `avg_pkt_size`, `flow_age_sec`)
que verás en los notebooks exploratorios:

```python
from src.detector import Detector
det = Detector.load("models/")

# flujo claramente normal (las 13 features con sus nombres canónicos)
det.predict({
    "src_port": 51234, "dst_port": 443, "protocol": 6,
    "packets_per_sec": 5.0, "bytes_per_sec": 4000.0,
    "avg_packet_size": 800.0, "flow_duration_sec": 2.5,
    "src_ip_entropy": 0.0, "dst_port_entropy": 0.0, "dst_ip_entropy": 0.0,
    "new_flows_per_sec": 0.5, "num_distinct_src_ips": 2, "num_distinct_dst_ips": 2,
})
# → DetectionResult(is_anomaly=False, attack_type='Normal', ...)
```

Suite completa de casos canónicos + evaluación sobre el CSV:

```bash
python test_bench.py
```

Para explorar los notebooks: `jupyter lab notebooks/`.

---

## 8. Operación en vivo (tres terminales)

Para detectar y mitigar ataques en vivo necesitas el stack completo. Cada proceso
en su terminal, dos *Python* distintos (el detector en `.venv` 3.11, Ryu en el del
sistema). Arquitectura y puertos detallados en [`INTERFACE.md`](INTERFACE.md).

```bash
# Terminal 1 — detector (venv 3.11)
source .venv/bin/activate
python serve_detector.py
# espera "Detector escuchando en 127.0.0.1:9999"

# Terminal 2 — Ryu (Python sistema; NO activar el venv aquí)
PYTHONPATH=. ryu-manager detect_app.py
# debe loguear "[detect] detector 127.0.0.1:9999 | persist=3 conf>=0.80 timeout=30s"

# Terminal 3 — Mininet con la topología y el tráfico que quieras probar
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=single,4 --switch=ovsk,protocols=OpenFlow13
mininet> h1 hping3 -S --faster 10.0.0.2     # ejemplo: SYN flood
```

Si el detector se cae, `detect_app` lo registra (`[detector caido?]`) pero sigue
corriendo: cada sondeo devuelve veredictos vacíos y no se mitiga. Levantar de
nuevo el detector retoma la conexión sin reiniciar Ryu.

---

## 9. (Opcional) Visualización con Grafana + InfluxDB

`detect_app.py` empuja métricas a InfluxDB (db `SDS`, puerto 8086) en cuanto la
encuentra arrancada — no requiere configuración adicional en el detector. Para
ver el dashboard:

```bash
sudo systemctl start influxdb grafana-server
```

En Grafana: añade el data source InfluxDB (URL `http://localhost:8086`, db `SDS`)
y luego **Dashboards → Import → Upload JSON file** → elige
[`grafana/sds_dashboard.json`](../grafana/sds_dashboard.json). Trae 11 paneles
listos (stats DoS/DDoS, series temporales con los picos de ataque, tablas de
IPs/MACs bloqueadas, reincidentes…). Detalles y queries en
[`grafana.md`](grafana.md).

---

## Problemas conocidos / notas

- **Python 3.8 del sistema:** no sirve. Si ves un error tipo
  `typing-extensions requires a different Python: 3.8.10 not in '>=3.9'`,
  es que el venv se creó con el Python viejo. Rehazlo con `uv` (paso 1-2).
- **PPA deadsnakes en focal:** no nos dio `python3.11` ni `python3.10` aunque
  el repo se añadía sin error. No perder tiempo ahí; usar `uv`.
- **`requirements.txt` sin versiones:** se han quitado los pines. Funciona, pero
  instala lo más reciente (p. ej. pandas 3.x, numpy 2.x). Si `src/train.py` peta
  con errores raros de pandas/numpy, fijar versiones más conservadoras
  (`pandas<3`, `numpy<2`) suele arreglarlo. **Recomendado:** una vez el
  entrenamiento funcione, congelar el entorno que SÍ funciona para el resto del
  equipo: `uv pip freeze > requirements.lock.txt`.
- **No mezclar este venv con el de Ryu.** Ryu pide Python viejo y es quisquilloso;
  el detector quiere Python moderno. Mantenerlos en entornos separados (el
  `INTERFACE.md` ya contempla que el detector pueda correr como proceso aparte).

---

## Versiones que funcionaron (referencia)

Entorno verificado el día del setup (Python 3.11.15, CPU):

```
torch==2.12.0+cpu
numpy==2.4.6
pandas==3.0.3
scikit-learn==1.8.0
xgboost==3.2.0
kagglehub==1.0.1
```
