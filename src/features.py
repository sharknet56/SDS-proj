"""Feature engineering compartido entre entrenamiento offline e inferencia online.

El módulo expone funciones puras (sin estado) para que las mismas
transformaciones que se aplican al entrenar con InSDN se apliquen al
tráfico en vivo dentro de la Ryu app.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


OPENFLOW_COMPATIBLE_FEATURES: list[str] = [
    "pkts_per_sec",
    "bytes_per_sec",
    "avg_pkt_size",
    "flow_age_sec",
    "src_ip_entropy",
    "dst_port_entropy",
    "new_flows_per_sec",
]


def shannon_entropy(values: pd.Series) -> float:
    counts = values.value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


def clean_insdn(df: pd.DataFrame) -> pd.DataFrame:
    """Limpia los problemas conocidos del dataset InSDN (Inf, NaN)."""
    df = df.replace([np.inf, -np.inf], np.nan)
    return df.dropna()
