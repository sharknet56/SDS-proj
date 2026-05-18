# Contrato entre subgrupos

Este documento define cómo se comunican el subgrupo de **detección** (modelo) y el subgrupo de **topología/bloqueo** (Mininet + Ryu).

**Estado:** borrador — pendiente de acordar con el subgrupo B.

## 1. Intervalo de polling

El controlador Ryu pide `OFPFlowStatsRequest` cada **2 segundos** (a confirmar). Cada ciclo de polling = una ventana de inferencia del modelo.

## 2. Features de entrada al detector

Por cada flow activo en la ventana, el controlador construye un diccionario con los siguientes campos:

### Crudas (directas de OpenFlow)

| Campo            | Tipo  | Origen                       |
|------------------|-------|------------------------------|
| `src_ip`         | str   | Match field                  |
| `dst_ip`         | str   | Match field                  |
| `src_port`       | int   | Match field                  |
| `dst_port`       | int   | Match field                  |
| `protocol`       | int   | Match field (6=TCP, 17=UDP)  |
| `packet_count`   | int   | Stats                        |
| `byte_count`     | int   | Stats                        |
| `duration_sec`   | int   | Stats                        |

### Derivadas (calculadas en el controlador entre dos polls)

| Campo                | Cálculo                                              |
|----------------------|------------------------------------------------------|
| `pkts_per_sec`       | Δpacket_count / Δt                                   |
| `bytes_per_sec`      | Δbyte_count / Δt                                     |
| `avg_pkt_size`       | byte_count / packet_count                            |
| `flow_age_sec`       | duration_sec                                         |

### Agregadas a nivel de ventana (TODO confirmar con grupo B quién las calcula)

| Campo                  | Cálculo                                            |
|------------------------|----------------------------------------------------|
| `src_ip_entropy`       | Entropía de Shannon de IPs origen en la ventana    |
| `dst_port_entropy`     | Entropía de Shannon de puertos destino             |
| `new_flows_per_sec`    | Flows nuevos en la ventana / Δt                    |

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
