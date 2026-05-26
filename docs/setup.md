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
- Acceso `sudo` para instalar paquetes del sistema (Mininet, OVS, Ryu, InfluxDB, Grafana).

Este proyecto se monta de cero — no asume ningún entorno previo. Sigue los pasos
en orden, cada uno deja la máquina lista para el siguiente.

---

## 0.5. Dependencias del sistema

**Mininet + OVS + hping3** (Python del sistema):
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3
sudo systemctl enable --now openvswitch-switch
```

**Ryu y la librería de InfluxDB** (Python 3.8 del sistema, NO el `.venv` de 3.11):
```bash
sudo apt install -y python3-pip
sudo pip3 install 'ryu==4.34' 'eventlet==0.30.2' 'influxdb<6'
```

> `eventlet` debe ser <0.31 — Ryu usa una API que rompió en 0.31. Si ves
> errores como `ALREADY_HANDLED` al arrancar `ryu-manager`, es esto.

Verifica:
```bash
ryu-manager --version    # debe responder algo como "ryu-manager 4.34"
which hping3             # /usr/sbin/hping3
mn --version             # 2.3.0+
```

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

## 4. Conseguir `data/dataset.csv`

El detector se entrena con un CSV capturado por nosotros en Mininet. Dos opciones:

**Opción A — usar el dataset que ya está en el repo.** Está versionado:

```bash
ls -lh data/dataset.csv     # debe pesar varios MB y traer la columna label
```

Si está, salta al paso 5.

**Opción B — capturarlo desde cero** (~25 min, necesita Mininet + sudo + Ryu del
sistema). Es un script que conduce Mininet por 15 escenarios canónicos:

```bash
sudo python3 scripts/capture_full.py
```

Sobre los escenarios y por qué son los que son, ver [`Summary.md` § Dataset](Summary.md#dataset).
Si solo quieres capturar una clase manualmente (útil para depurar), está
documentado en `CLAUDE.md` y en la cabecera de `capture_app.py`.

---

## 5. Entrenar

```bash
python -m src.train
```

- Lee `data/dataset.csv` (capturado en el paso anterior). **No descarga InSDN.**
- Tarda ~1 min en CPU.
- Al acabar deja los artefactos en `models/` (scaler, autoencoder, XGBoost,
  label encoder, metadatos) e imprime accuracy y F1 macro (debería rondar 0.99).

---

## 6. Probar el detector (sin Mininet)

Las features que espera el detector son las 13 canónicas de `src/live_features.py:COLUMNS`:

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

Suite completa de casos canónicos + evaluación sobre el CSV + lógica de
mitigación (con Ryu stubbeado para que el test corra desde el `.venv`):

```bash
python test_bench.py
```

---

## 7. Operación en vivo (tres terminales)

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

## 8. Visualización: InfluxDB + Grafana

`detect_app.py` empuja métricas a InfluxDB y Grafana las pinta. Ambos forman parte
del stack del proyecto — no son opcionales.

### 8.1. Instalar InfluxDB 1.x

La librería python `influxdb<6` que usa `detect_app.py` habla con InfluxDB v1
(no v2/Flux), así que necesitamos la rama 1.x:

```bash
sudo apt install -y influxdb influxdb-client
sudo systemctl enable --now influxdb
```

### 8.2. Instalar Grafana

Grafana no viene en los repos por defecto de focal — hay que añadir el suyo:

```bash
sudo apt install -y software-properties-common gnupg wget
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update
sudo apt install -y grafana
sudo systemctl enable --now grafana-server
```

### 8.3. Verificar que ambos están vivos

Antes de seguir, comprueba que los dos servicios responden:

```bash
# InfluxDB: el endpoint /ping debe devolver 204
curl -sS -o /dev/null -w "InfluxDB: HTTP %{http_code}\n" http://127.0.0.1:8086/ping
# esperado: "InfluxDB: HTTP 204"

# Listar databases (al principio solo verás "_internal"; la SDS se creará sola
# cuando arranques detect_app.py por primera vez)
curl -sS "http://127.0.0.1:8086/query?q=SHOW+DATABASES"
# esperado: {"results":[{"statement_id":0,"series":[{"name":"databases","columns":["name"],"values":[["_internal"]]}]}]}

# Grafana: el endpoint /api/health debe devolver 200 con database: "ok"
curl -sS http://127.0.0.1:3000/api/health
# esperado: {"commit":"...","database":"ok","version":"..."}

# systemd debería marcar ambos como "active"
systemctl is-active influxdb grafana-server
# esperado: dos líneas "active"
```

Si alguna comprobación falla, antes de seguir resuélvelo (típicamente
`journalctl -u influxdb -n 50` o `journalctl -u grafana-server -n 50`).

### 8.4. Importar el dashboard

Cuando los dos servicios estén OK, en Grafana (`http://localhost:3000`, login
por defecto `admin` / `admin`, te pedirá cambiar la contraseña):

1. **Connections → Data sources → Add data source → InfluxDB.**
   - URL: `http://localhost:8086`
   - Database: `SDS`
   - HTTP Method: `GET`
   - Pulsa **Save & Test**. Debe decir "datasource is working" (la db `SDS`
     puede no existir aún si no has lanzado `detect_app.py`; Grafana se
     queja pero la conexión vale).
2. **Dashboards → New → Import → Upload JSON file** → elige
   [`grafana/sds_dashboard.json`](../grafana/sds_dashboard.json) y selecciona
   el data source que acabas de crear. Trae 11 paneles listos (stats DoS/DDoS,
   series temporales con los picos de ataque, tablas de IPs/MACs bloqueadas,
   reincidentes…).

Detalles de las queries y de cada panel en [`grafana.md`](grafana.md).

---

## Problemas conocidos / notas

- **Python 3.8 del sistema:** no sirve para el detector. Si ves un error tipo
  `typing-extensions requires a different Python: 3.8.10 not in '>=3.9'`,
  es que el venv se creó con el Python viejo. Rehazlo con `uv` (paso 1-2).
- **PPA deadsnakes en focal:** no nos dio `python3.11` ni `python3.10` aunque
  el repo se añadía sin error. No perder tiempo ahí; usar `uv`.
- **No mezclar el venv 3.11 con el Python del sistema.** Ryu pide Python 3.8 y
  es quisquilloso con eventlet; el detector quiere Python 3.11. Cada uno en su
  entorno (el bridge es el socket TCP de [`INTERFACE.md`](INTERFACE.md)). En
  particular, no instales `ryu` dentro del `.venv` ni `torch` en el sistema.
- **`eventlet` versión:** Ryu solo funciona con `eventlet<0.31`. Si arrancas
  `ryu-manager` y revienta con `ALREADY_HANDLED` o errores de greenthread,
  `sudo pip3 install 'eventlet==0.30.2'`.
- **`torch==2.12.0+cpu` en el lock:** `requirements.txt` lo pinea como `torch==2.12.0`
  (sin `+cpu`). PEP 440 trata `2.12.0+cpu` como variante local de `2.12.0`, así
  que el pin se cumple. La instrucción del paso 3 (instalar `torch` antes desde
  el índice CPU) sigue siendo la forma correcta de evitar la descarga de CUDA.

---

## Versiones que funcionaron (referencia)

Entorno verificado el día del setup (Python 3.11.15, CPU). Idéntico a
[`requirements.txt`](../requirements.txt):

```
numpy==2.4.6
pandas==3.0.3
scikit-learn==1.8.0
xgboost==3.2.0
torch==2.12.0   (variante +cpu instalada desde el índice CPU)
joblib==1.5.3
```

Y en el Python del sistema (para Ryu / capture):

```
ryu==4.34
eventlet==0.30.2
influxdb<6
```
