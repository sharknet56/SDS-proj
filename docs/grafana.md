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
| `blocks` | al aplicar una mitigación (`active=1`) y al expirar (`active=0`) | `type` (DoS/DDoS), `target` | `active`, `expires` |

Para DoS, `target` es la IP origen bloqueada (drop por `ipv4_src`).
Para DDoS, `target` es la MAC origen bloqueada (drop por `eth_src`).

---

## 3. Conectar Grafana a InfluxDB

Configuration → Data Sources → Add data source → InfluxDB:
- **URL:** `http://localhost:8086`
- **Database:** `SDS`
- Sin usuario ni contraseña. Guardar (Save & Test).

---

## 4. Importar el dashboard (rápido)

El dashboard completo está en [`grafana/sds_dashboard.json`](../grafana/sds_dashboard.json).
Se importa entero desde la UI:

1. **Dashboards → New → Import** (o `+` en la barra lateral → Import).
2. **Upload JSON file** y elige `grafana/sds_dashboard.json`.
3. En el paso "Options", asigna el data source **InfluxDB** que acabas de crear.
4. **Import**.

Lo que aparece, en este orden:

| Fila | Paneles |
|------|---------|
| 1 (stats) | Ataques DoS · Ataques DDoS · Flujos vivos · Racha de ataques |
| 2 (series) | Flujos vs ataques · Diversidad de fuentes (`num_distinct_src_ips` + `src_ip_entropy`) |
| 3 (series + barras) | Episodios por hora (DoS/DDoS) · Nuevos flujos/s + entropía de puerto destino |
| 4 (tablas) | DoS · IPs bloqueadas (activas y pasadas) · DDoS · MACs bloqueadas (activas y pasadas) |
| 5 (tabla ancha) | Reincidentes — nº de bloqueos por origen (IP o MAC) |

Refresco: 5 s. Ventana por defecto: últimos 15 min.

---

## 5. Paneles (referencia de queries)

Si prefieres montarlos a mano o entender qué hace cada uno, esta es la lista de queries
en InfluxQL. Son las mismas que usa el JSON de arriba.

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

### DDoS — MACs bloqueadas (activas y pasadas)

Panel **Table**. Una fila por MAC; `activo=1` está bloqueada ahora, `activo=0`
fue un bloqueo que ya expiró. `target` es la MAC origen del atacante:

```sql
SELECT last("active") AS "activo", last("expires") AS "expira_unix"
FROM "blocks"
WHERE "type" = 'DDoS' AND $timeFilter
GROUP BY "target"
```

Mismo Transform que en el panel de DoS para convertir `expira_unix` a hora.

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

## 6. Notas

- **Conflictos de tipo en InfluxDB:** si cambias el tipo de un campo entre
  ejecuciones (p. ej. un entero pasa a flotante), InfluxDB se queja. Si ocurre,
  borra y recrea la medida: `influx` → `USE SDS` → `DROP MEASUREMENT "blocks"`.
- **Las escrituras son cada 2 s** desde la app de Ryu; para el demo va sobrado.
- **El countdown del timeout** no se muestra "vivo" en una tabla; se muestra la
  hora de expiración (`expires`). Una mitigación con `active=1` cuyo `expires` ya
  pasó se marcará como `active=0` en el siguiente sondeo.
