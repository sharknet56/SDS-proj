"""Extracción de features en vivo desde flow-stats de OpenFlow.

Módulo PURO y COMPARTIDO: lo usan tanto la captura del dataset
(capture_app.py) como la detección en vivo. Calcular las features en un solo
sitio garantiza que sean idénticas al entrenar y al desplegar (sin skew).

Dos tipos de feature:
  - PER_FLOW: una fila por flujo activo en cada sondeo (las 7 de siempre).
  - WINDOW:   un valor por sondeo, igual para todas las filas de esa ventana.
              Son las que distinguen DoS (1 fuente) de DDoS (muchas fuentes).
"""
from __future__ import annotations

import math
from collections import Counter

PER_FLOW = [
    "src_port", "dst_port", "protocol",
    "packets_per_sec", "bytes_per_sec", "avg_packet_size", "flow_duration_sec",
]
WINDOW = [
    "src_ip_entropy", "dst_port_entropy", "new_flows_per_sec", "num_distinct_src_ips",
]
COLUMNS = PER_FLOW + WINDOW          # orden de columnas del CSV (sin la etiqueta)


def mget(match, key, default=0):
    """Acceso seguro a un campo del OFPMatch (default si el campo no está).

    Si tu versión de Ryu se queja aquí, este es el primer sitio a revisar.
    """
    try:
        return match[key]
    except KeyError:
        return default


def _src_port(match):
    return mget(match, "tcp_src") or mget(match, "udp_src") or 0


def _dst_port(match):
    return mget(match, "tcp_dst") or mget(match, "udp_dst") or 0


def flow_key(stat) -> str:
    """Identificador estable de un flujo (para detectar flujos nuevos por ventana)."""
    m = stat.match
    return (f"{mget(m, 'ipv4_src', '')}|{mget(m, 'ipv4_dst', '')}|"
            f"{mget(m, 'ip_proto', '')}|{_dst_port(m)}")


def shannon_entropy(values) -> float:
    """Entropía de Shannon (en bits) de una lista de valores categóricos.

    Mide la 'diversidad': 0 si todos son iguales (1 fuente), alta si hay muchas
    fuentes distintas y equiprobables (típico de un DDoS spoofeado).
    """
    if not values:
        return 0.0
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in Counter(values).values())


def per_flow_features(stat, prev: dict, poll_interval: float) -> dict:
    """Las 7 features de UN flujo.

    `prev` es {flow_key: (pkts, bytes)} del sondeo anterior, para calcular el
    delta (tráfico ocurrido durante la ventana, no el acumulado del flujo).
    """
    m = stat.match
    pkts, byts = stat.packet_count, stat.byte_count
    dur = stat.duration_sec + stat.duration_nsec / 1e9
    ppkts, pbyts = prev.get(flow_key(stat), (0, 0))
    dpkts = max(pkts - ppkts, 0)
    dbyts = max(byts - pbyts, 0)
    return {
        "src_port": _src_port(m),
        "dst_port": _dst_port(m),
        "protocol": mget(m, "ip_proto"),
        "packets_per_sec":  dpkts / poll_interval,
        "bytes_per_sec": dbyts / poll_interval,
        "avg_packet_size":  (byts / pkts) if pkts else 0.0,
        "flow_duration_sec":  dur,
    }


def window_features(stats, prev_keys: set, poll_interval: float) -> tuple[dict, set]:
    """Features agregadas de TODA la ventana (un único valor por sondeo).

    Devuelve (dict_de_features, claves_de_este_sondeo) para que el llamante
    guarde las claves y en el siguiente sondeo sepa cuáles son nuevas.
    """
    src_ips = [mget(s.match, "ipv4_src", None) for s in stats]
    src_ips = [ip for ip in src_ips if ip]
    dst_ports = [_dst_port(s.match) for s in stats]
    keys_now = {flow_key(s) for s in stats}
    new_flows = len(keys_now - prev_keys)
    feats = {
        "src_ip_entropy":    shannon_entropy(src_ips),
        "dst_port_entropy":  shannon_entropy(dst_ports),
        "new_flows_per_sec": new_flows / poll_interval,
        "num_distinct_src_ips":    len(set(src_ips)),
    }
    return feats, keys_now
