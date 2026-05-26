# Visualización con Grafana + InfluxDB

Panel de monitorización del detector/mitigador, usando el stack del Lab 4
(InfluxDB 1.8 + Grafana). `detect_app.py` escribe las métricas; Grafana las pinta.

---

## 1. Requisitos

InfluxDB y Grafana instalados y arrancados (Lab 4):

```bash
sudo systemctl start influxdb
sudo systemctl start grafana-server
```

`detect_app.py` necesita el cliente de InfluxDB en el **Python del sistema** (ya
instalado en el Lab 4; si no: `sudo apt-get install -yq python3-influxdb`). Crea
la base de datos `SDS` automáticamente al arrancar (no hace falta tocar InfluxDB).

Al lanzar `PYTHONPATH=. ryu-manager detect_app.py` deberías ver en el log:
`[influx] conectado a 127.0.0.1:8086 db=SDS`. Si ves `[influx] no disponible`,
revisa que InfluxDB esté arrancado; la detección sigue funcionando igual.

---

## 2. Qué escribe `detect_app` en InfluxDB (db `SDS`)

| Measurement | Cuándo | Tags | Campos |
|-------------|--------|------|--------|
| `detection` | cada sondeo (2 s) | `type` (predominante) | `total_flows`, `attacks`, `normal`, `dos`, `ddos`, `num_distinct_src_ips`, `src_ip_entropy`, `dst_port_entropy`, `new_flows_per_sec`, `attack_streak` |
| `attack_event` | al **empezar** cada episodio de ataque | `type` | `count`(=1), `num_src`, `entropy` |
| `blocks` | al aplicar una mitigación (`active=1`) y al expirar (`active=0`) | `type` (DoS/DDoS), `target` | `active`, `expires`, `port`, `rate_kbps`, `ratelimited` |

Para DoS, `target` es la IP origen bloqueada. Para DDoS, `target` es `víctima:puerto`.

---

## 3. Conectar Grafana a InfluxDB

Configuration → Data Sources → Add data source → InfluxDB:
- **URL:** `http://localhost:8086`
- **Database:** `SDS`
- Sin usuario ni contraseña. Guardar (Save & Test).

Crear un dashboard nuevo e ir añadiendo paneles con las queries de abajo
(pestaña Query → data source InfluxDB → editar en modo texto/raw).

---

## 4. Paneles

### DoS — IPs bloqueadas (activas y pasadas)

Panel **Table**. Una fila por IP; `activo=1` está bloqueada ahora, `activo=0` fue
un bloqueo que ya expiró:

```sql
SELECT last("active") AS "activo", last("expires") AS "expira_unix"
FROM "blocks"
WHERE "type" = 'DoS' AND $timeFilter
GROUP BY "target"
```

Truco: en Transform puedes convertir `expira_unix` (segundos) a hora, y ordenar
por `activo` para ver primero las activas.

### DDoS — rate-limiting actual y a qué puerto

Panel **Table**. `es_ratelimit=1` significa que hay rate-limiting activo (meter);
`=0` es el fallback de bloqueo. `target` es `víctima:puerto`:

```sql
SELECT last("active") AS "activo", last("port") AS "puerto",
       last("rate_kbps") AS "kbps", last("ratelimited") AS "es_ratelimit"
FROM "blocks"
WHERE "type" = 'DDoS' AND $timeFilter
GROUP BY "target"
```

### DDoS — histórico de entropía

Panel **Time series**. La entropía de IPs origen durante los sondeos clasificados
como DDoS (se dispara en los ataques distribuidos):

```sql
SELECT mean("src_ip_entropy")
FROM "detection"
WHERE "type" = 'DDoS' AND $timeFilter
GROUP BY time($__interval) fill(none)
```

Variante útil: nº de fuentes distintas a lo largo del tiempo (`max("num_distinct_src_ips")`).

### Frecuencia de ataques (cada cuánto llega uno)

Panel **Time series** o **Bar chart**. Ataques por hora, separados por tipo:

```sql
SELECT count("count")
FROM "attack_event"
WHERE $timeFilter
GROUP BY time(1h), "type" fill(0)
```

Media del intervalo entre ataques DDoS (avanzado, con `ELAPSED`), en segundos:

```sql
SELECT mean("gap") FROM (
  SELECT elapsed("count", 1s) AS "gap"
  FROM "attack_event" WHERE "type" = 'DDoS'
) WHERE $timeFilter
```

### Conteo total de ataques por tipo

Paneles **Stat** (un número):

```sql
SELECT count("count") FROM "attack_event" WHERE "type" = 'DoS'  AND $timeFilter
SELECT count("count") FROM "attack_event" WHERE "type" = 'DDoS' AND $timeFilter
```

### (Opcional) Tráfico vs ataques en el tiempo

Panel **Time series** para ver el panorama general:

```sql
SELECT mean("total_flows") AS "flujos", mean("attacks") AS "ataques"
FROM "detection"
WHERE $timeFilter
GROUP BY time($__interval) fill(0)
```

---

## 5. Notas

- **Conflictos de tipo en InfluxDB:** si cambias el tipo de un campo entre
  ejecuciones (p. ej. un entero pasa a flotante), InfluxDB se queja. Si ocurre,
  borra y recrea la medida: `influx` → `USE SDS` → `DROP MEASUREMENT "blocks"`.
- **Las escrituras son cada 2 s** desde la app de Ryu; para el demo va sobrado.
- **El countdown del timeout** no se muestra "vivo" en una tabla; se muestra la
  hora de expiración (`expires`). Una mitigación con `active=1` cuyo `expires` ya
  pasó se marcará como `active=0` en el siguiente sondeo.
