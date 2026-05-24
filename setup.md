# Setup — Detector DDoS (subgrupo A)

Guía para levantar el detector desde cero en una máquina nueva (Ubuntu 20.04 / VM).
Esta es la ruta que **realmente** ha funcionado, no la teórica del README.

> **Resumen de 10 segundos:** el sistema trae Python 3.8, que ya no vale.
> Usamos `uv` para tener Python 3.11 sin pelearnos con apt, y de ahí todo va seguido.

---

## 0. Requisitos previos

- Ubuntu 20.04 (focal) o similar. CPU, sin GPU (entrenamos en CPU).
- ~10 GB de disco libres (sobra con 60). El grueso es PyTorch (~200 MB el wheel, ~3-4 GB el entorno).
- Una cuenta de Kaggle (para descargar el dataset InSDN).

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

## 4. Token de Kaggle (`.env`)

El dataset InSDN se descarga con `kagglehub`, que necesita credenciales.
Crea un token en <https://www.kaggle.com/settings> → *Create new token* y mételo
en un fichero `.env` **en la raíz del repo** (ya está en `.gitignore`):

```bash
echo "KAGGLE_API_TOKEN=tu_token_aqui" > .env
```

Alternativa clásica: `KAGGLE_USERNAME=...` y `KAGGLE_KEY=...` en el mismo `.env`.

---

## 5. Entrenar

```bash
python -m src.train
```

- La primera vez descarga InSDN (~0,5-1 GB), se cachea en `~/.cache/kagglehub`.
- Tarda ~1-2 min en CPU.
- Al acabar, deja los modelos en `models/` e imprime un F1 (debería rondar 0.99).

---

## 6. Probar el detector (sin Mininet)

```python
from src.detector import Detector
det = Detector.load("models/")

# flujo claramente normal
det.predict({
    "src_port": 51234, "dst_port": 443, "protocol": 6,
    "pkts_per_sec": 5.0, "bytes_per_sec": 4000.0,
    "avg_pkt_size": 800.0, "flow_age_sec": 2.5,
})
# → is_anomaly=False, attack_type='Normal'
```

Para explorar los notebooks: `jupyter lab notebooks/`.

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
