# Contrato entre subgrupos

Este documento define cómo se comunican el subgrupo de **detección** (modelo) y el subgrupo de **topología/bloqueo** (Mininet + Ryu).

**Estado:** borrador — pendiente de acordar con el subgrupo B.

## 1. Intervalo de polling

El controlador Ryu pide `OFPFlowStatsRequest` cada **2 segundos** (a confirmar). Cada ciclo de polling = una ventana de inferencia del modelo.

## 2. Features de entrada al detector

Confirmado tras EDA de InSDN: el modelo "desplegable" usa el siguiente subconjunto, todo derivable de stats de OpenFlow sin inspección de paquetes.

### Por flow (un diccionario por flow activo en la ventana)

| Campo            | Tipo  | Origen                                   |
|------------------|-------|------------------------------------------|
| `src_ip`         | str   | Match field                              |
| `dst_ip`         | str   | Match field                              |
| `src_port`       | int   | Match field                              |
| `dst_port`       | int   | Match field                              |
| `protocol`       | int   | Match field (6=TCP, 17=UDP, 1=ICMP)      |
| `pkts_per_sec`   | float | Δpacket_count / Δt entre dos polls       |
| `bytes_per_sec`  | float | Δbyte_count / Δt entre dos polls         |
| `avg_pkt_size`   | float | byte_count / packet_count                |
| `flow_age_sec`   | float | duration_sec + duration_nsec / 1e9       |

### Agregadas en la ventana de polling (un valor por ventana)

| Campo                  | Cálculo                                            |
|------------------------|----------------------------------------------------|
| `src_ip_entropy`       | Entropía de Shannon de IPs origen en la ventana    |
| `dst_port_entropy`     | Entropía de Shannon de puertos destino             |
| `new_flows_per_sec`    | Flows nuevos en la ventana / Δt                    |

Estas agregadas se calculan en `src/features.py` (función `window_features`) — se pueden calcular en el detector o en la Ryu app, a acordar.

### Por qué NO usamos las features de IAT y flags TCP

InSDN incluye 84 features. La mayoría (IAT mean/std/min/max, conteos de flags SYN/ACK/RST, packet length distributions) **requieren inspección de paquetes** y no se pueden obtener desde stats de OpenFlow estándar. Las descartamos para que el modelo entrenado offline use exactamente lo mismo que tendrá disponible en vivo.

Como referencia académica, mantendremos también un "modelo full" entrenado con las 84 features para reportar el techo de rendimiento en la memoria.

## 3. Llamada al detector

```python
from src.detector import Detector

detector = Detector.load("models/")

# Por cada ventana de polling:
result = detector.predict(features_dict)
```

`features_dict` puede ser un `dict` (un flow) o `pd.DataFrame` (varios flows).

## 4. Formato del evento de alerta

Cuando el detector marca un flow/ventana como anómalo, devuelve:

```json
{
  "timestamp": 1715000000,
  "victim_ip": "10.0.0.4",
  "src_ip": "10.0.0.2",
  "attack_type": "syn_flood",
  "confidence": 0.93,
  "is_anomaly": true
}
```

Tipos de ataque posibles (a refinar tras el EDA de InSDN): `syn_flood`, `udp_flood`, `icmp_flood`, `http_flood`, `slowloris`, `unknown`.

## 5. Acción del subgrupo B

El subgrupo B decide qué hacer con la alerta (instalar regla de drop por IP origen, por flow específico, rate-limit, etc.). El detector solo emite la alerta.

## 6. Puntos pendientes de acordar

- [ ] Intervalo exacto de polling.
- [ ] ¿Quién calcula las entropías agregadas, el controlador o el detector?
- [ ] ¿Granularidad de la alerta: por flow o por víctima agregada?
- [ ] ¿Empaquetado del detector: módulo Python importable o servicio aparte (ZeroMQ)?
- [ ] Lista cerrada de tipos de ataque a clasificar.
