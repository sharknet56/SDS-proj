"""Feature engineering compartido entre entrenamiento offline e inferencia online.

El módulo expone funciones puras (sin estado) para que las mismas
transformaciones que se aplican al entrenar con InSDN se apliquen al
tráfico en vivo dentro de la Ryu app.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


OPENFLOW_COMPATIBLE_FEATURES: list[str] = [
    "src_port",
    "dst_port",
    "protocol",
    "pkts_per_sec",
    "bytes_per_sec",
    "avg_pkt_size",
    "flow_age_sec",
    "src_ip_entropy",
    "dst_port_entropy",
    "new_flows_per_sec",
]

# Mapeo entre columnas de InSDN y los nombres de feature que la Ryu app
# producirá en vivo. Solo se mapean features derivables desde stats de
# OpenFlow (no IAT, no flags TCP, no header lengths).
INSDN_TO_OPENFLOW: dict[str, str] = {
    "Src Port": "src_port",
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Flow Pkts/s": "pkts_per_sec",
    "Flow Byts/s": "bytes_per_sec",
    "Pkt Size Avg": "avg_pkt_size",
    "Flow Duration": "flow_age_sec",  # InSDN lo da en µs, convertir a s
}

# Columnas a descartar para evitar fugas o porque no son features:
# - Flow ID, Src IP, Dst IP: identificadores no aprendibles.
# - Timestamp: el modelo no debe depender de la hora.
INSDN_DROP_COLS: list[str] = ["Flow ID", "Src IP", "Dst IP", "Timestamp"]


def shannon_entropy(values: pd.Series) -> float:
    counts = values.value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


def clean_insdn(df: pd.DataFrame) -> pd.DataFrame:
    """Limpia los problemas conocidos del dataset InSDN (Inf, NaN)."""
    df = df.replace([np.inf, -np.inf], np.nan)
    return df.dropna()
