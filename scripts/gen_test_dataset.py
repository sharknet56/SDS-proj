#!/usr/bin/env python3
"""Genera data/test.csv sintético para el banco de pruebas.

Uso (desde la raíz del repo, dentro del venv del detector):
    python scripts/gen_test_dataset.py
    python scripts/gen_test_dataset.py --n-per-class 500 --seed 7

Por qué existe este script
--------------------------
test_bench.py recomienda usar data/test.csv (datos INDEPENDIENTES) en lugar de
data/dataset.csv (los de entrenamiento). Capturar una sesión nueva con Mininet
es lo ideal, pero requiere levantar la topología, los atacantes, etc. Este
script ofrece una alternativa rápida: muestrea flujos por clase desde
distribuciones paramétricas inspiradas en

  - los CASES canónicos de test_bench.py (vectores PASS/FAIL conocidos),
  - los rangos observados en data/dataset.csv por clase,
  - el comportamiento de los ataques que usamos en captura
    (hping3 --flood, --rand-source, ICMP/SYN floods).

Es un test SINTÉTICO. Sirve para detectar regresiones rápidas y para que las
métricas de test_bench.py no estén medidas contra los datos de entrenamiento,
pero NO sustituye una captura real con Mininet.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "test.csv"

FEATURES = [
    "src_port", "dst_port", "protocol",
    "packets_per_sec", "bytes_per_sec", "avg_packet_size",
    "flow_duration_sec",
    "src_ip_entropy", "dst_port_entropy",
    "new_flows_per_sec", "num_distinct_src_ips",
]


# ---------------------------------------------------------------------------
# Generadores por clase
# ---------------------------------------------------------------------------
def _clip(x, lo, hi):
    return np.clip(x, lo, hi)


def gen_normal(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """Tráfico legítimo: mezcla de pings, navegación HTTP y descargas pesadas.

    El reto del Normal es que incluye un caso "single-source de alto volumen"
    (iperf / descarga) que el modelo NO debe confundir con un flood.
    """
    rows = []
    for _ in range(n):
        kind = rng.choice(["icmp_idle", "http_browse", "bulk_download"],
                          p=[0.30, 0.45, 0.25])
        if kind == "icmp_idle":
            proto = 1
            dport = 0
            pps = _clip(rng.normal(2, 1.5), 0, 20)
            avg = _clip(rng.normal(98, 8), 50, 200)
            bps = pps * avg
            age = _clip(rng.normal(8, 4), 0.5, 60)
            n_src = rng.choice([2, 3, 4, 5], p=[0.5, 0.3, 0.15, 0.05])
            new_f = _clip(rng.normal(0.2, 0.3), 0, 2)
            src_ent = _clip(rng.normal(1.6, 0.15), 1.0, 2.3)
            dport_ent = _clip(rng.normal(2.5, 1.5), 0, 4.7)
        elif kind == "http_browse":
            proto = 6
            dport = int(rng.choice([80, 443, 8080, 3000]))
            pps = _clip(rng.normal(50, 40), 1, 800)
            avg = _clip(rng.normal(800, 400), 60, 1500)
            bps = pps * avg
            age = _clip(rng.normal(5, 3), 0.5, 30)
            n_src = rng.choice([2, 3, 4, 5], p=[0.4, 0.35, 0.2, 0.05])
            new_f = _clip(rng.normal(0.8, 0.8), 0, 4)
            src_ent = _clip(rng.normal(1.7, 0.15), 1.0, 2.3)
            dport_ent = _clip(rng.normal(4.0, 0.8), 0, 4.7)
        else:  # bulk_download
            proto = 6
            dport = int(rng.choice([80, 443, 5001]))
            # iperf-like: muchos paquetes/seg, paquetes grandes
            pps = _clip(rng.normal(40000, 15000), 5000, 100000)
            avg = _clip(rng.normal(40000, 10000), 1400, 60000)
            bps = pps * avg
            age = _clip(rng.normal(3, 1), 0.5, 20)
            n_src = rng.choice([2, 3, 4], p=[0.7, 0.25, 0.05])
            new_f = _clip(rng.normal(1.0, 0.6), 0, 3)
            src_ent = _clip(rng.normal(1.7, 0.15), 1.0, 2.3)
            dport_ent = _clip(rng.normal(1.5, 1.0), 0, 4.7)

        rows.append([0, dport, proto, pps, bps, avg, age,
                     src_ent, dport_ent, new_f, n_src])

    df = pd.DataFrame(rows, columns=FEATURES)
    df["label"] = "normal"
    return df


def gen_dos(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """DoS de una sola fuente: ICMP flood y SYN flood, con hping3 --flood."""
    rows = []
    for _ in range(n):
        kind = rng.choice(["icmp_flood", "syn_flood", "udp_flood"],
                          p=[0.35, 0.5, 0.15])
        if kind == "icmp_flood":
            proto = 1
            dport = 0
            pps = _clip(rng.normal(3000, 800), 200, 20000)
            avg = _clip(rng.normal(42, 8), 28, 100)
            dport_ent = _clip(rng.normal(0.5, 0.5), 0, 2)
        elif kind == "syn_flood":
            proto = 6
            dport = int(rng.choice([80, 443, 22, 8080]))
            pps = _clip(rng.normal(5000, 1500), 200, 50000)
            avg = _clip(rng.normal(60, 8), 40, 120)
            dport_ent = _clip(rng.normal(0.3, 0.3), 0, 2)
        else:  # udp_flood
            proto = 17
            dport = int(rng.choice([53, 123, 161, 5060]))
            pps = _clip(rng.normal(8000, 2500), 200, 30000)
            avg = _clip(rng.normal(120, 40), 28, 1470)
            dport_ent = _clip(rng.normal(0.4, 0.4), 0, 2)

        bps = pps * avg
        age = _clip(rng.normal(15, 8), 1, 60)
        # DoS de 1 fuente: poca entropía de src, pocas IPs distintas
        n_src = rng.choice([1, 2], p=[0.7, 0.3])
        new_f = _clip(rng.normal(2, 2), 0, 15)
        src_ent = _clip(rng.normal(0.2, 0.3), 0, 1.6)

        rows.append([0, dport, proto, pps, bps, avg, age,
                     src_ent, dport_ent, new_f, n_src])

    df = pd.DataFrame(rows, columns=FEATURES)
    df["label"] = "dos"
    return df


def gen_ddos(rng: np.random.Generator, n: int) -> pd.DataFrame:
    """DDoS: spoofeado (--rand-source) o atacantes reales distribuidos."""
    rows = []
    for _ in range(n):
        kind = rng.choice(["rand_source", "distributed_real"], p=[0.65, 0.35])
        proto = 6  # casi siempre TCP en este dataset
        dport = int(rng.choice([80, 443, 22]))

        if kind == "rand_source":
            # --rand-source: cada paquete IP distinta → mucha entropía, MUCHAS IPs
            n_src = int(_clip(rng.normal(180, 90), 20, 600))
            src_ent = _clip(rng.normal(6.5, 1.5), 3.0, 9.2)
            pps = _clip(rng.normal(1.5, 1.0), 0.1, 50)  # por flujo (cada IP=1 flujo)
            avg = _clip(rng.normal(60, 10), 40, 120)
            new_f = _clip(rng.normal(200, 60), 5, 292)
        else:
            # Atacantes reales distribuidos: pocas IPs (~10-30), entropía moderada
            n_src = int(_clip(rng.normal(15, 8), 5, 50))
            src_ent = _clip(rng.normal(2.5, 0.8), 1.0, 4.5)
            pps = _clip(rng.normal(400, 200), 50, 5000)
            avg = _clip(rng.normal(80, 30), 40, 200)
            new_f = _clip(rng.normal(20, 15), 5, 100)

        bps = pps * avg
        age = _clip(rng.normal(20, 10), 1, 80)
        dport_ent = _clip(rng.normal(6.5, 2.0), 0, 9.2)

        rows.append([0, dport, proto, pps, bps, avg, age,
                     src_ent, dport_ent, new_f, n_src])

    df = pd.DataFrame(rows, columns=FEATURES)
    df["label"] = "ddos"
    return df


# ---------------------------------------------------------------------------
# Entrada
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-per-class", type=int, default=400,
                    help="Filas por clase (default: 400)")
    ap.add_argument("--seed", type=int, default=42,
                    help="Semilla del RNG (default: 42)")
    ap.add_argument("--out", type=Path, default=OUT,
                    help=f"Ruta de salida (default: {OUT.relative_to(ROOT)})")
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    n = args.n_per_class

    parts = [
        gen_normal(rng, n),
        gen_dos(rng, n),
        gen_ddos(rng, n),
    ]
    df = pd.concat(parts, ignore_index=True)
    # Mezclamos para que test_bench no procese todo en bloques por clase
    df = df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    try:
        shown = args.out.relative_to(ROOT)
    except ValueError:
        shown = args.out
    print(f"Escrito {shown} ({len(df)} filas)")
    print(df["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
