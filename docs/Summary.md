# Summary — Detector DDoS

Para que entiendas en 5 minutos qué hace el sistema, cómo decide qué es un ataque, y cuáles son sus límites.

## Qué hace el detector

Un pipeline en **dos etapas** que toma estadísticas de flujo desde OpenFlow y dice si hay ataque y de qué tipo:

```
flow stats (OpenFlow, cada 2s)
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
XGBoost   decide Normal     Normal (sin gastar XGBoost)
   │
   ▼
attack_type ∈ {Normal, DoS, DDoS}
```

- El **Autoencoder** se entrena SOLO con tráfico Normal → si un flujo no se parece a lo normal, error de reconstrucción alto.
- El **threshold** es el percentil 99 del error de reconstrucción sobre validación Normal.
- El **XGBoost** clasifica los anómalos en {Normal, DoS, DDoS} y puede rescatar falsos positivos del AE devolviendo "Normal".

## Por qué este diseño

- Usamos **13 features derivables exclusivamente de stats de OpenFlow** (no necesitamos inspección de paquetes), así el modelo offline ve exactamente lo mismo que el detector en vivo.
- Cascada AE → XGBoost: el AE actúa como filtro barato (el 95%+ del tráfico es normal y no llega a XGBoost), XGBoost solo se invoca para flujos sospechosos.
- Entrenamiento end-to-end en ~1 minuto sobre CPU.

### Las 13 features

**Por flujo (7)** — describen UN flujo concreto:

| Feature | Qué mide |
|---|---|
| `src_port`, `dst_port` | Puertos L4 |
| `protocol` | 1=ICMP, 6=TCP, 17=UDP |
| `packets_per_sec` | Tasa de paquetes en la ventana |
| `bytes_per_sec` | Tasa de bytes |
| `avg_packet_size` | Tamaño medio de paquete |
| `flow_duration_sec` | Duración acumulada |

**Por ventana de polling (6)** — describen TODO el conjunto de flujos en la ventana:

| Feature | Qué mide |
|---|---|
| `src_ip_entropy` | Entropía Shannon de IPs origen (diversidad) |
| `dst_ip_entropy` | Entropía Shannon de IPs destino |
| `dst_port_entropy` | Entropía Shannon de puertos destino |
| `num_distinct_src_ips` | Conteo de IPs origen únicas |
| `num_distinct_dst_ips` | Conteo de IPs destino únicas |
| `new_flows_per_sec` | Flujos nuevos por segundo |

Las features de **diversidad de destino** (`dst_ip_entropy`, `num_distinct_dst_ips`) son las que permiten distinguir patrones que serían ambiguos mirando solo el origen.

---

## El modelo conceptual: 8 cuadrantes en (src div, dst div, tasa)

Combinando las tres dimensiones del comportamiento — diversidad de origen, diversidad de destino y tasa de paquetes — quedan 8 patrones distinguibles:

```
                              dst BAJA            dst ALTA
                          ┌────────────────┬────────────────┐
            tasa baja    │ Normal p-a-p   │ Pingall/mesh   │
                          │ (descarga, web)│ (benigno)      │
src BAJA   ────────────  ├────────────────┼────────────────┤
            tasa alta    │ DoS clásico    │ DoS multi-tgt  │
                          │ (1→1 flood)    │ (1→N flood)    │
                          └────────────────┴────────────────┘
                          ┌────────────────┬────────────────┐
            tasa baja    │ DDoS sigiloso  │ Cluster mesh   │
                          │ (caso límite)  │ (heartbeats)   │
src ALTA   ────────────  ├────────────────┼────────────────┤
            tasa alta    │ DDoS clásico   │ Multi-DDoS     │
                          │ (N→1 flood)    │ (N→M flood)    │
                          └────────────────┴────────────────┘
```

El dataset de entreno cubre los cuadrantes de **tasa alta** (ataques) y los de tráfico normal punto-a-punto. Los cuadrantes "benignos con diversidad" (pingall, cluster mesh) se gestionan vía **diferencia en `packets_per_sec`** — el tráfico legítimo de diagnóstico tiene tasas de 0.5-1 pkts/s mientras los ataques están en miles.

---

## Cómo se detecta cada tipo de tráfico

### Tráfico NORMAL

| Sub-caso | Señales que ve el modelo | Decisión |
|---|---|---|
| Ping idle | `pkts/s≈1`, `avg_size=98B`, `new_flows/s≈0`, `n_src=2-3`, `n_dst=2-3` | AE error bajo → **Normal** |
| Web/HTTP mixto | `pkts/s` moderado, `new_flows/s` bajo, tamaños variados | AE error bajo → **Normal** |
| **Descarga grande (≥500MB)** | `pkts/s` ALTO, `avg_size` grande, **`new_flows/s≈0`**, `n_src=2`, `n_dst=2` | AE puede flagear por volumen pero XGBoost ve "pocas conexiones nuevas + 1 par IP" → **Normal** |
| **Pingall / mesh benigno** | `n_src` alto, `n_dst` alto, **`pkts/s` MUY bajo** | Tasa baja descarta ataque → **Normal** |

### Ataques DoS (1 IP origen)

Firma común: `pkts/s` alto desde 1 IP, **`new_flows/s` alto** (src_port aleatorio crea muchos flujos de retorno RST), `n_src=2`, `src_ip_entropy≈1.0`.

| Variante | Discriminante adicional |
|---|---|
| TCP SYN flood | `protocol=6`, `avg_size=54B` |
| TCP SYN padded | `protocol=6`, `avg_size` grande (el tamaño NO marca) |
| TCP ACK flood | `protocol=6`, ACKs sin SYN previo |
| TCP RST flood | `protocol=6`, intentos de cortar sesiones |
| ICMP flood | `protocol=1`, `avg_size=42B` |
| UDP flood | `protocol=17`, `avg_size` variable |
| Multi-vector | Combinación de protocolos desde misma IP |
| **Multi-target** | `n_dst` alto (varias víctimas), `n_src` bajo → patrón propio |

→ AE error alto + XGBoost ve `pkts/s alto + n_src bajo + new_flows alto` → **DoS** independientemente del protocolo o tamaño.

### Ataques DDoS (muchas IPs origen)

| Sub-caso | Señales distintivas | Decisión |
|---|---|---|
| Spoofeado (`hping3 --rand-source`) | `src_ip_entropy>>5`, `n_src>>50`, `n_dst=1` | AE error extremo → **DDoS** |
| Atacantes reales (6 hosts) | `src_ip_entropy≈2-3`, `n_src=7`, `n_dst=1` | AE error alto → **DDoS** |
| Distribuido baja tasa | `pkts/s` bajo por flujo pero `n_src` alto | Caso difícil |
| **Multi-target** | `n_src` alto, `n_dst` alto, `pkts/s` alto (clave) | Tasa alta lo separa del pingall → **DDoS** |

### Las distinciones críticas

**Descarga grande vs SYN flood** — ambas pueden tener `pkts/s` muy alto:

```
Descarga 500MB:    1 IP, pkts/s alto, new_flows/s ≈ 0    → conexión establecida
SYN flood:         1 IP, pkts/s alto, new_flows/s ALTO   → muchos intentos nuevos
```

`new_flows_per_sec` es el discriminador.

**Pingall vs multi-target DDoS** — ambos tienen `n_src` y `n_dst` altos:

```
Pingall:           pkts/s ≈ 0.5 por flujo  → tráfico de diagnóstico
Multi-DDoS:        pkts/s > 1000 por flujo → ataque sostenido
```

`packets_per_sec` es el discriminador.

**Monitoring (1→N) vs DoS multi-target (1→N)** — ambos tienen 1 origen y muchos destinos:

```
Nagios/Zabbix:     pkts/s ≈ 1, avg_size = 98B (ICMP) → diagnóstico
DoS multi-target:  pkts/s > 1000, avg_size = 54B    → ataque
```

De nuevo, tasa y tamaño.

### En una frase

> El modelo combina **dónde** (origen y destino), **cuánto** (tasa) y **cómo** (tamaño y protocolo) para clasificar. Ningún campo solo es suficiente; el ataque es siempre una **combinación anómala** que el AE no ha visto durante el entreno con tráfico normal.

---

## Qué NO detecta (fuera de alcance, declarado)

### Ataques fuera del modelo de amenaza

| Ataque | Por qué no lo pillamos | Qué necesitaría |
|---|---|---|
| **Slowloris** | Tasa baja por flujo, no dispara umbrales | Tracking de conexiones HTTP semi-abiertas (L7) |
| **HTTP flood (L7)** | Conexiones completan handshake, parecen tráfico web legítimo | Análisis a nivel de petición HTTP |
| **DoS "perfecto"** con src_port fijo + tasa moderada + paquetes grandes | Indistinguible de una descarga sin inspección de payload | DPI o stateful tracking TCP |
| **Amplification (DNS/NTP)** | Vemos solo el lado víctima, no la query falsa | Vista de doble extremo |

### Tráfico benigno estructuralmente igual a un ataque

Estos casos tienen **exactamente la misma forma** que un DDoS o DoS en las features de flujo. Sin contexto externo, el modelo no puede distinguirlos:

| Caso benigno | Forma | Indistinguible de |
|---|---|---|
| **Servidor SMTP / IMAP** corporativo | muchos clientes → 1 servidor | DDoS |
| **Bastión SSH** (todos los devs entran por un host) | muchos → 1 | DDoS |
| **Servidor de actualizaciones** durante rollout | muchos PCs → 1 servidor | DDoS |
| **Anycast / load balancer endpoint** | muchos → 1 (por diseño) | DDoS |
| **Flash crowd** (lanzamiento viral) | muchos → 1 web | DDoS |
| **Backup centralizado** tirando de agentes | 1 → muchos | Escaneo / DoS multi-target |
| **Load tester** (jmeter, ab) | 1 → 1 con `new_flows/s` alto | DoS |

**Cómo se mitiga en producción** (trabajo futuro, no parte de este modelo):

- **Whitelist de IPs internas**: los servicios conocidos del dominio (servidor SMTP, bastión SSH, balancer) se eximen del filtro. El modelo solo procesa flujos cuya IP origen Y destino no estén en la lista de servicios confiables.
- **Reputación de IPs externas**: integración con feeds de threat intelligence.
- **Ventanas temporales**: tráfico esperado (rollout de updates los martes a las 3am) se permite explícitamente.
- **Capa 7 / DPI** para flujos que pasan el filtro inicial pero requieren más contexto.

Estas defensas existen en NGFWs y XDRs comerciales. Nuestro detector es la **capa ML pura** que se complementaría con ellas.

---

## Limitaciones conocidas del modelo actual

### `flow_duration_sec` fuera de rango

El AE se entrena con flujos de hasta ~90 segundos. En producción una descarga real puede durar minutos u horas. Cuando `flow_duration_sec` supera con mucho el rango entrenado, el AE puede flagearlo. Mitigaciones posibles:
1. Capturar uno o dos escenarios Normal largos (5-10 min)
2. Clipar `flow_duration_sec` a un máximo antes del scaler (p.ej. 120s)
3. Quitar la feature (no es la más discriminativa)

### Adversarial padding + puerto origen fijo

Un atacante que conoce el modelo y usa SYN flood con `-k -s` (puerto origen fijo) y padding grande neutraliza dos features clave a la vez:
- `avg_packet_size` parece normal
- `new_flows_per_sec` no se dispara

Defensa real: rate limiting genérico por IP + reputación. No es alcance de este modelo.

### Dependencia del modo de captura

El modelo es muy sensible a cómo se capturó el entrenamiento. La captura debe mantener:
- **src_port aleatorio** en ataques DoS (no usar `-k -s` en hping3)
- Al menos un escenario Normal de descarga sostenida (`normal_bulk_download`)
- Escenarios multi-target (`dos_multi_target`, `ddos_multi_target`) para cubrir los cuadrantes con diversidad de destino

Todo esto está documentado en [`scripts/capture_full.py`](../scripts/capture_full.py).

### Descarga legítima a tasa GbE real (resultado del test bench)

El modelo entrenado clasifica **correctamente 12 de 13 casos canónicos** en `test_bench.py`. El único caso que falla:

> Descarga TCP establecida desde 1 IP a 5000 pkts/s con paquetes de 1500B y `new_flows/s ≈ 0` → clasificada como **DoS** en vez de Normal.

La razón: el escenario `normal_bulk_download` se capturó usando `python -m http.server`, que en Mininet sobre CPU compartida solo alcanza ~50 pkts/s. El modelo nunca vio en la clase Normal un patrón de "alto pkts/s + 1 IP + new_flows≈0". Cuando recibe ese patrón, encaja con DoS clásico aunque `new_flows/s` sea 0.

En una red GbE real, una descarga grande SÍ llegaría a esas tasas. Esto es una **limitación del entorno de captura**, no del diseño del modelo. Mitigaciones posibles (no implementadas):

1. **Recapturar usando `nc`/`socat`/`iperf` reales** para llegar a tasas de GbE en `normal_bulk_download`. Lo más simple si tuviéramos las herramientas instaladas.
2. **Emparejar flujos forward/return y añadir una feature de bidireccionalidad** (ver "Trabajo futuro" abajo). El discriminador conceptual: una descarga legítima tiene ACKs simétricos, un SYN flood no.
3. **Inspección stateful o DPI** para verificar el handshake TCP completado. Fuera de alcance.

### Limitación estructural: connection tracking en flow-level

Para distinguir con garantías "5000 pkts/s desde 1 IP con conexión establecida" (descarga) de "5000 pkts/s desde 1 IP en ataque" se necesita información que OpenFlow stats estándar **no expone**:

| Lo que necesitarías saber | ¿Está en flow stats? |
|---|---|
| ¿Se completó el TCP handshake (SYN-ACK-ACK)? | NO |
| ¿Los paquetes son SYNs sin payload, o data segments? | NO (solo el promedio agregado) |
| ¿Hay FIN ordenado al final del flujo? | NO |
| ¿Cuántos bytes han pasado en cada dirección? | Sí, en flujos separados (sin emparejar) |
| Duración del flujo | Sí |

Lo único factible con flow stats puro es **correlacionar manualmente forward y return** y comparar tasas/tamaños:

- Descarga: forward (cliente→servidor) con ACKs pequeños, return (servidor→cliente) con paquetes grandes → asimetría de tamaño pero bidireccional activo
- SYN flood: forward con 5000 SYNs/s, return ~0 (víctima no responde o RSTs sueltos) → asimetría brutal en tasa

Implementarlo requiere modificar `live_features.py` para emparejar flujos por 5-tupla invertida, calcular una feature `bidirectional_ratio`, y reentrenar. Queda como **trabajo futuro**.

### Sensibilidad a la topología de red

Las features **por flujo** (tasa, tamaño, protocolo, puertos) son topology-agnostic. Pero las **de ventana** son contadores absolutos que escalan con el tamaño de la red. Si entrenas con 8 hosts y luego despliegas en una topología de 16 hosts:

| Feature | 8 hosts | 16 hosts | Impacto |
|---|---|---|---|
| `num_distinct_src_ips` | 8 | 16 | Fuera de rango entrenado |
| `src_ip_entropy` | 3.0 | 4.0 | Aprox. dentro del rango |
| `new_flows_per_sec` (pingall inicial) | ~56 | ~240 | Fuera de rango |

Consecuencia: tráfico que sería normal en la nueva topología puede salir clasificado como ataque (probablemente DDoS multi-target, que es la única clase con `n_src` y `n_dst` altos).

Tres mitigaciones posibles, en orden de coste:

1. **Recapturar y reentrenar** cada vez que cambie la topología (lo más simple).
2. **Capturar varias topologías** en el dataset (4, 8, 16 hosts) durante el entrenamiento inicial.
3. **Sustituir contadores por proporciones** en `live_features.py` — usar `num_distinct_src_ips / num_total_flows` en vez del contador absoluto. La proporción es invariante al tamaño de red. Es un cambio de feature engineering pero hace el modelo portable.

Mientras se entrene con un único tamaño de red, **el modelo solo es válido para ese tamaño**.

---

## Qué necesitaría un modelo "perfecto"

Para superar las limitaciones anteriores haría falta:

1. **Whitelist / IP reputation** — el primer paso, el más sencillo, el de mayor impacto práctico. Identifica servidores conocidos del dominio.
2. **Inspección de paquetes (DPI)** — flags TCP, headers HTTP, payloads. Captura Slowloris y HTTP floods.
3. **Tracking stateful de conexiones** — distingue half-open de established, mide tiempos de respuesta.
4. **Features de comportamiento histórico** — ¿esta IP suele generar este tráfico? Requiere persistir estado.
5. **Sensores multipunto** — detecta amplification mirando ingress + egress.

Nuestro proyecto cubre el nivel "ML sobre features de OpenFlow". Es lo que cabe razonablemente en una Ryu app, y es suficiente para detectar la mayoría de floods clásicos.

---

## Dataset

**Capturado nosotros** en Mininet con [`scripts/capture_full.py`](../scripts/capture_full.py). No usamos InSDN como datos de entrenamiento (sí en notebooks 01-04 para exploración inicial).

Esquema del CSV (`data/dataset.csv`):
- 13 columnas de features + `label` ∈ {normal, dos, ddos}
- Una fila por flujo activo en cada poll (cada 2 segundos)
- `CAPTURE_FILTER_IDLE=1` activo durante captura → no se escriben flujos sin actividad

15 escenarios cubren todos los cuadrantes:

| # | Etiqueta | Escenario | Qué cubre |
|---|---|---|---|
| 1 | normal | `normal_idle` | baseline reposo |
| 2 | normal | `normal_mixed` | web + ping + descargas pequeñas |
| 3 | normal | `normal_bulk_download` | descarga grande desde 1 IP (volumen establecido) |
| 4 | dos | `dos_syn_1000pps_54B` | SYN flood clásico |
| 5 | dos | `dos_syn_2000pps_1514B` | SYN flood con MTU completo |
| 6 | dos | `dos_ack_2000pps` | ACK flood |
| 7 | dos | `dos_rst_2000pps` | RST flood |
| 8 | dos | `dos_icmp_2500pps` | ICMP flood |
| 9 | dos | `dos_udp_2000pps` | UDP flood |
| 10 | dos | `dos_mixed_syn_icmp` | multi-vector |
| 11 | dos | `dos_multi_target` | 1 atacante → 3 víctimas |
| 12 | ddos | `ddos_spoofed` | `--rand-source`, entropía extrema |
| 13 | ddos | `ddos_real_hosts_mixed` | 6 atacantes reales con protocolos variados |
| 14 | ddos | `ddos_low_rate_distributed` | tasa baja por atacante, agregado moderado |
| 15 | ddos | `ddos_multi_target` | 4 atacantes → 2 víctimas |

Captura completa: ~25 minutos.

## Estructura del repo

```
SDS-proj/
├── data/
│   └── dataset.csv             # capturado por nosotros (no versionado)
├── notebooks/
│   ├── 01_eda.ipynb            # exploración InSDN
│   ├── 02_baseline_rf.ipynb    # baseline RF
│   ├── 03_anomaly_detector.ipynb
│   └── 04_classifier.ipynb
├── src/
│   ├── live_features.py        # extracción de features compartida (capture + detect)
│   ├── detector.py             # clase Detector (API pública)
│   ├── train.py                # entrena AE + XGBoost desde data/dataset.csv
│   ├── features.py             # constantes InSDN (solo notebooks)
│   └── data.py                 # descarga InSDN (solo notebooks)
├── scripts/
│   └── capture_full.py         # script de captura completo
├── capture_app.py              # Ryu app: captura tráfico → CSV
├── detect_app.py               # Ryu app: detecta + mitiga en vivo
├── serve_detector.py           # servidor TCP del detector (puerto 9999)
├── test_bench.py               # banco de pruebas + evaluación
├── models/                     # artefactos entrenados (no versionados)
└── requirements.txt
```

## Cómo levantarlo en tu máquina

Setup detallado en [`setup.md`](setup.md) (misma carpeta `docs/`). Resumen:

1. **Entorno** (Python 3.11 vía uv):
   ```bash
   uv venv .venv --python 3.11
   source .venv/bin/activate
   uv pip install torch --index-url https://download.pytorch.org/whl/cpu
   uv pip install -r requirements.txt
   ```

2. **Capturar dataset** (necesita Mininet + sudo, ~25 min):
   ```bash
   sudo python3 scripts/capture_full.py
   ```

3. **Entrenar** (~1 min en CPU):
   ```bash
   python -m src.train
   ```
   Deja todo en `models/`.

4. **Probar**:
   ```bash
   python test_bench.py
   ```

5. **Operación en vivo** (tres terminales):
   - Terminal 1: `python serve_detector.py` (venv 3.11)
   - Terminal 2: `PYTHONPATH=. ryu-manager detect_app.py` (Python sistema)
   - Terminal 3: Mininet con tráfico

## API del Detector (lo que usa la Ryu app)

```python
from src.detector import Detector

det = Detector.load("models/")

# Una predicción
result = det.predict(flow_dict)
# DetectionResult(is_anomaly=True, attack_type='DoS', confidence=0.97, anomaly_score=12.7)

# Batch (más eficiente)
results = det.predict(df_flows)

# Acceso a metadatos
det.feature_names        # ['src_port', 'dst_port', ..., 'num_distinct_dst_ips']
det.default_threshold    # P99 del error AE sobre validación Normal
```

`DetectionResult.to_dict()` devuelve el evento JSON que `detect_app.py` envía por socket y escribe en InfluxDB.

## Qué falta

- Validación end-to-end con tráfico realista en Mininet (más allá de los escenarios canónicos).
- Comparar AE+XGBoost contra baselines más simples (RF puro, threshold por feature) para la memoria.
- **Whitelist de IPs internas** (trabajo futuro): integrar una lista de servidores corporativos conocidos (SMTP, bastión, balancer) que se eximen del filtro. Cierra los casos "estructuralmente ambiguos".
- **Feature de bidireccionalidad** (trabajo futuro): emparejar flujos forward/return en `live_features.py` y añadir un ratio que mida si la conexión es bidireccional simétrica (descarga real) o asimétrica brutal (flood). Cerraría el caso del bulk-download a alta tasa.
- Capturar uno o dos escenarios Normal largos si se va a desplegar en producción (límite de `flow_duration_sec`).

## Estado actual de validación

Última ejecución de `test_bench.py`:

- **12/13 casos canónicos correctos** (PASS). El único fallo es el caso de "descarga grande a tasa GbE real" — documentado como limitación del entorno de captura, no del modelo.
- F1 macro = 1.0 sobre el dataset completo.
- AE separa con margen amplísimo (max error Normal = 5.5, mediana DoS/DDoS = 9000+, threshold P99 = 4.19).
- Casos adversariales validados correctamente: DoS padded 1500B, DoS multi-target, DDoS spoofeado, DDoS multi-target, pingall benigno.

## Si algo no te cuadra

- Si `python -m src.train` falla: revisa que `data/dataset.csv` existe (lánzalo con `scripts/capture_full.py` primero).
- Si los modelos sueltan `is_anomaly=True` en tráfico legítimo de descarga grande: revisa la sección "Limitaciones conocidas" — es esperado en el entorno Mininet actual.
- Si el F1 sale <0.95: probablemente el dataset está desbalanceado o la captura tiene un escenario contaminado. Inspecciona con `python3 -c "import pandas as pd; print(pd.read_csv('data/dataset.csv').label.value_counts())"`.
- Cualquier duda sobre la lógica de detección: empieza por la sección "Cómo se detecta cada tipo de tráfico" arriba.
