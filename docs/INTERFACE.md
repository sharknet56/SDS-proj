# Arquitectura desplegada

Cómo se conectan las piezas del sistema en producción y por qué están así.

> Este documento describe el sistema **tal como está desplegado hoy**. Para
> entender el modelo de detección en sí (cómo decide qué es ataque, features
> usadas, escenarios cubiertos) → [`Summary.md`](Summary.md).

---

## Vista de pájaro

```
                ┌─────────────────────────────────────────────────────────┐
                │  Mininet (red SDN simulada)                             │
                │   h1, h2, ..., hN  ↔  OVS switch (s1)                   │
                └───────────────────────────┬─────────────────────────────┘
                                            │ OpenFlow 1.3
                                            ▼
              ┌─────────────────────────────────────────────────────┐
              │  detect_app.py  (Ryu app, Python sistema)           │
              │  ─ instala flujos por (IP src, IP dst, proto, port) │
              │  ─ sondea FlowStats cada 2 s                        │
              │  ─ calcula 13 features con src/live_features.py     │
              │  ─ aplica mitigación (drop o rate-limit con meter)  │
              └────┬──────────────────────────────┬─────────────────┘
                   │                              │
   TCP JSON-lines  │                              │  HTTP write
   127.0.0.1:9999  │                              │  127.0.0.1:8086
                   ▼                              ▼
   ┌──────────────────────────────┐   ┌───────────────────────────┐
   │  serve_detector.py           │   │  InfluxDB (db "SDS")      │
   │  (Python 3.11 venv)          │   │   detection / attack_event│
   │   ─ Detector.load("models/") │   │   /  blocks               │
   │   ─ AE → XGBoost cascade     │   └───────────┬───────────────┘
   └──────────────────────────────┘               │
                                                  ▼
                                       ┌───────────────────┐
                                       │  Grafana (visual) │
                                       └───────────────────┘
```

Tres procesos, tres terminales, dos *Python* distintos. La razón por la
que está partido así está en [§ Por qué dos venvs](#por-qué-dos-venvs).

---

## Componentes y responsabilidades

### 1. `detect_app.py` — Ryu app (Python del sistema, 3.8)

| Responsabilidad | Detalle |
|---|---|
| L2 learning switch | Aprende MACs, instala flujos por par IP+puerto destino+protocolo. |
| Polling | `OFPFlowStatsRequest` cada `POLL=2` s (`hub.spawn`). |
| Feature extraction | Llama a `src.live_features.per_flow_features` (7) y `window_features` (6). |
| Inferencia | Envía cada flow como JSON line al detector, lee veredicto. |
| Persistencia anti-falso-positivo | Solo mitiga tras `MIT_PERSISTENCE=3` sondeos consecutivos con ataque y `confidence ≥ MIT_MIN_CONF=0.80`. |
| Mitigación | **DoS** → drop por IP origen (hard_timeout=30 s). **DDoS** → rate-limit a `DDOS_RATE_KBPS=1000` por OVS meter sobre (IP dst, puerto), con fallback a drop si los meters fallan. |
| Telemetría | Escribe 3 measurements en InfluxDB (`detection`, `attack_event`, `blocks`). |

Lo que **no** hace: clasificación. Toda la lógica ML vive en el otro proceso.

### 2. `serve_detector.py` — servidor del detector (venv 3.11)

Servidor `ThreadingTCPServer` en `127.0.0.1:9999`. Por cada línea JSON
entrante con las 13 features, devuelve una línea JSON con el veredicto.

```python
# Entrada (una línea por flow)
{"src_port": 0, "dst_port": 80, "protocol": 6,
 "packets_per_sec": 2000, "bytes_per_sec": 108000,
 "avg_packet_size": 54, "flow_duration_sec": 5.0,
 "src_ip_entropy": 0.0, "dst_port_entropy": 9.0, "dst_ip_entropy": 0.0,
 "new_flows_per_sec": 292.0,
 "num_distinct_src_ips": 2, "num_distinct_dst_ips": 2}

# Salida
{"is_anomaly": true, "attack_type": "DoS",
 "confidence": 0.9871, "anomaly_score": 12.7234}
```

Carga `models/` una vez al arrancar (`Detector.load`) y reutiliza.
Cada conexión es persistente: el cliente manda múltiples líneas y lee
las respuestas en orden (una a una). Errores se devuelven como
`{"error": "..."}` en la misma línea.

### 3. `src/detector.py` — la clase `Detector`

API pública que ambos lados consumen:

```python
det = Detector.load("models/")
result = det.predict(features)               # umbral P99 fijo del entreno
result = det.predict(features, threshold=t)  # override (umbral dinámico)
```

Internamente: `StandardScaler` → `Autoencoder` (PyTorch, 13→16→8→4→8→16→13)
→ si `score > threshold` invoca XGBoost multiclase {Normal, DoS, DDoS}; si no,
devuelve `Normal` sin gastar CPU. Si XGBoost dice "Normal" sobre un flujo
anómalo del AE, rescata el falso positivo.

### 4. InfluxDB + Grafana

`detect_app.py` empuja 3 measurements en la db `SDS` (puerto 8086):

| Measurement | Frecuencia | Sirve para |
|---|---|---|
| `detection` | cada sondeo (2 s) | series temporales de flujos, entropías, conteos |
| `attack_event` | una al iniciar episodio | frecuencia/histórico de ataques |
| `blocks` | al aplicar (`active=1`) y al expirar (`active=0`) | ciclo de vida de las mitigaciones |

Queries de Grafana y configuración en [`grafana.md`](grafana.md).

---

## Por qué dos venvs

Ryu (estable, 4.x) está pegado a Python 3.6-3.8 y depende de eventlet, que
peta con CPython moderno. PyTorch / pandas / xgboost recientes requieren
3.9+. La intersección es **vacía**.

Solución: dos procesos, dos intérpretes, IPC por socket.

- **Detector** (`serve_detector.py`): venv `.venv/` con Python 3.11 (instalado
  por `uv`).
- **Controlador Ryu** (`detect_app.py`, `capture_app.py`): Python del sistema
  con `ryu-manager` instalado vía apt o pip user-site.

El bridge — JSON sobre TCP — está documentado arriba. El coste es ~1 ms por
flow en localhost; despreciable frente a los 2 s de polling.

---

## Flujo end-to-end de un ataque (DoS clásico)

1. `t=0` — `hping3 -S --faster <víctima>` arranca desde `h1`.
2. `t=0..2` — Ryu instala los flujos en OVS al ver el primer paquete.
3. `t=2` — primer `FlowStatsReply`. `detect_app` calcula features,
   envía 13 floats por la TCP al detector.
4. `t=2.001` — detector responde `{attack_type: "DoS", confidence: 0.97}`.
   `detect_app` empieza a contar racha (streak=1).
5. `t=4`, `t=6` — sondeos 2 y 3. Streak llega a 3.
6. `t=6` — se cumple `MIT_PERSISTENCE=3`. `detect_app` instala
   `OFPFlowMod` con `ipv4_src=10.0.0.1`, instrucciones vacías
   (drop), `hard_timeout=30 s`. Escribe `blocks active=1` en InfluxDB.
7. `t=36` — la regla expira sola. `_prune_blocks` escribe `active=0`.

Si la confianza queda <0.80 o la racha se rompe (un sondeo sin ataque),
no se mitiga. Por eso un blip aislado no genera bloqueo.

---

## Puertos, paths y configuración

| Recurso | Dónde se cambia | Default |
|---|---|---|
| Puerto detector ↔ Ryu | `DETECTOR_ADDR` en `detect_app.py`, hardcoded en `serve_detector.py` | `127.0.0.1:9999` |
| Intervalo de polling | `POLL` en `detect_app.py` y `capture_app.py` | `2 s` |
| Persistencia mitigación | `MIT_PERSISTENCE`, `MIT_MIN_CONF`, `MIT_TIMEOUT` en `detect_app.py` | `3, 0.80, 30 s` |
| Tasa rate-limit DDoS | `DDOS_RATE_KBPS` en `detect_app.py` | `1000 kbps` |
| Usar meters OVS | `USE_METER` en `detect_app.py` (poner `False` si tu OVS no los soporta) | `True` |
| InfluxDB | `INFLUX_HOST/PORT/DB` en `detect_app.py` | `127.0.0.1:8086 / SDS` |
| Umbral AE | `AE_THRESHOLD_PERCENTILE` en `src/train.py` (regenera modelos al cambiarlo) | `99` |

---

## Contrato de datos al detector

13 features, en este orden (ver `src/live_features.py:COLUMNS`):

```
src_port, dst_port, protocol,
packets_per_sec, bytes_per_sec, avg_packet_size, flow_duration_sec,
src_ip_entropy, dst_port_entropy, dst_ip_entropy,
new_flows_per_sec, num_distinct_src_ips, num_distinct_dst_ips
```

Mandar el dict como JSON-line; sobran claves se ignoran, falta alguna y
`Detector._to_dataframe` lanza `ValueError` (qué falta lo dice el mensaje).

---

## Qué procesos hay que tener vivos para que funcione

| Orden | Proceso | Terminal / venv | Comando |
|---|---|---|---|
| 1 | InfluxDB y Grafana (si quieres visualización) | sistema | `sudo systemctl start influxdb grafana-server` |
| 2 | Detector | venv 3.11 | `source .venv/bin/activate && python serve_detector.py` |
| 3 | Ryu controller | python sistema | `PYTHONPATH=. ryu-manager detect_app.py` |
| 4 | Mininet (topología + tráfico) | sistema, root | `sudo mn --controller=remote ...` o `sudo python3 scripts/capture_full.py` para una sesión guiada |

Si el detector se cae, `detect_app` lo registra (`[detector caido?]`) pero
sigue corriendo: cada sondeo devuelve veredictos vacíos y no se mitiga.
Levantar de nuevo el detector retoma la conexión sin reiniciar Ryu.
