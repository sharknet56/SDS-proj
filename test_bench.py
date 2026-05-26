"""Banco de pruebas del detector entrenado.

Ejecutar en el venv 3.11, desde la raíz del repo:
    python test_bench.py

Dos partes:
  1) Casos canónicos: vectores de features representativos de cada situación,
     con el resultado esperado (PASS/FAIL). Incluye el caso del iperf de alto
     volumen, que antes daba falso positivo (prueba de regresión).
  2) Evaluación sobre un CSV completo: usa data/test.csv si existe (datos
     INDEPENDIENTES, lo ideal); si no, data/dataset.csv (sanity check sobre los
     datos de entrenamiento). Imprime exactitud y matriz de confusión.
"""
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from src.detector import Detector

ROOT = Path(__file__).resolve().parent
LABEL_MAP = {"normal": "Normal", "dos": "DoS", "ddos": "DDoS"}

det = Detector.load(ROOT / "models")
print("Detector cargado. Features:", det.feature_names)
print("=" * 70)


# ---------------------------------------------------------------------------
# Parte 1 — casos canónicos
# ---------------------------------------------------------------------------
def case(src_port, dst_port, protocol, pps, bps, avg_size, age,
         src_ent, dport_ent, dst_ent, new_flows, n_src, n_dst):
    return {
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "packets_per_sec": pps, "bytes_per_sec": bps, "avg_packet_size": avg_size,
        "flow_duration_sec": age,
        "src_ip_entropy": src_ent, "dst_port_entropy": dport_ent,
        "dst_ip_entropy": dst_ent,
        "new_flows_per_sec": new_flows,
        "num_distinct_src_ips": n_src, "num_distinct_dst_ips": n_dst,
    }


# (descripción, features, ¿es ataque?, tipo esperado)
# Recordatorio del patrón src/dst:
#   normal punto-a-punto: src/dst ambos bajos (1-3 IPs)
#   DoS:                  1 IP origen → 1+ víctimas (src bajo)
#   DDoS:                 muchas IPs origen → 1+ víctimas (src alto)
#   pingall (benigno):    malla (src alto, dst alto, tasa MUY baja)
#
# Valores extraídos de muestras reales del dataset capturado.
CASES = [
    # ---------- NORMAL ----------
    ("Normal: ping idle (ICMP a 1 pkt/s)",
     case(0, 0, 1, 1, 98, 98, 5.0,
          src_ent=1.5, dport_ent=0.0, dst_ent=1.5,
          new_flows=0.0, n_src=3, n_dst=3), False, "Normal"),
    ("Normal: HTTP browsing (varios clientes, tasa baja)",
     case(0, 8000, 6, 30, 2028, 67.6, 1.6,
          src_ent=2.25, dport_ent=2.5, dst_ent=2.25,
          new_flows=4.0, n_src=5, n_dst=5), False, "Normal"),
    ("Normal: descarga grande establecida (1 IP, alto vol, new_flows=0) [REGRESION]",
     case(0, 8000, 6, 5000, 7500000, 1500, 30.0,
          src_ent=1.0, dport_ent=0.0, dst_ent=1.0,
          new_flows=0.0, n_src=2, n_dst=2), False, "Normal"),
    ("Normal: pingall malla benigno (caso límite) [REGRESION]",
     case(0, 0, 1, 0.5, 49, 98, 3.0,
          src_ent=3.0, dport_ent=0.0, dst_ent=3.0,
          new_flows=20.0, n_src=8, n_dst=8), False, "Normal"),

    # ---------- DoS ----------
    ("DoS: ICMP flood (42B, alta tasa, 1 fuente)",
     case(0, 0, 1, 2500, 105000, 42, 25.0,
          src_ent=0.0, dport_ent=1.5, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),
    ("DoS: SYN flood clásico (54B, src_port aleatorio)",
     case(0, 80, 6, 2000, 108000, 54, 5.0,
          src_ent=0.0, dport_ent=9.0, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),
    ("DoS: SYN flood PADDED 1500B (evade avg_packet_size) [ADVERSARIAL]",
     case(0, 80, 6, 695, 1052987, 1514, 1.2,
          src_ent=0.018, dport_ent=9.19, dst_ent=0.018,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),
    ("DoS: ACK flood (paquetes pequeños sin SYN)",
     case(0, 80, 6, 2000, 108000, 54, 10.0,
          src_ent=0.0, dport_ent=9.0, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),
    ("DoS: UDP flood (puerto 53, payload 100B)",
     case(0, 53, 17, 2000, 280000, 140, 15.0,
          src_ent=0.0, dport_ent=0.0, dst_ent=0.0,
          new_flows=20.0, n_src=2, n_dst=2), True, "DoS"),
    ("DoS: multi-target (1 atacante → 3 víctimas)",
     case(0, 80, 6, 542, 29295, 54, 4.2,
          src_ent=1.62, dport_ent=7.65, dst_ent=0.05,
          new_flows=292.0, n_src=4, n_dst=4), True, "DoS"),

    # ---------- DDoS ----------
    ("DDoS: spoofeado (--rand-source, entropía extrema)",
     case(0, 80, 6, 1.0, 60, 60, 12.8,
          src_ent=8.36, dport_ent=0.0, dst_ent=0.0,
          new_flows=164.0, n_src=328, n_dst=1), True, "DDoS"),
    ("DDoS: 6 atacantes reales (entropía moderada)",
     case(0, 80, 6, 230, 12420, 54, 1.8,
          src_ent=1.07, dport_ent=7.23, dst_ent=2.05,
          new_flows=292.0, n_src=6, n_dst=6), True, "DDoS"),
    ("DDoS: multi-target (4 atacantes → 2 víctimas)",
     case(0, 80, 1, 180, 7560, 42, 1.2,
          src_ent=0.11, dport_ent=7.62, dst_ent=1.68,
          new_flows=292.5, n_src=7, n_dst=6), True, "DDoS"),
]

print("PARTE 1 - Casos canonicos\n")
passed = 0
for desc, feats, is_attack, exp_type in CASES:
    r = det.predict(feats)
    # El criterio PASS/FAIL es la DETECCION (ataque vs normal).
    detection_ok = (r.is_anomaly == is_attack)
    type_ok = (r.attack_type == exp_type)
    passed += detection_ok
    print(f"  [{'PASS' if detection_ok else 'FAIL'}] {desc}")
    print(f"         is_anomaly={r.is_anomaly} (esperado ataque={is_attack})   "
          f"tipo={r.attack_type} (esperado={exp_type}) {'OK' if type_ok else 'XX'}   "
          f"conf={r.confidence:.2f}")
print(f"\n  -> Deteccion correcta en {passed}/{len(CASES)} casos")
print("=" * 70)


# ---------------------------------------------------------------------------
# Parte 2 — evaluacion sobre un CSV
# ---------------------------------------------------------------------------
test_csv = ROOT / "data" / "test.csv"
if test_csv.exists():
    csv_path, independent = test_csv, True
else:
    csv_path, independent = ROOT / "data" / "dataset.csv", False

print(f"PARTE 2 - Evaluacion sobre {csv_path.name}")
if not independent:
    print("  AVISO: son los datos de entrenamiento -> sanity check, NO test independiente.")
    print("  Para un test real, captura data/test.csv en una sesion nueva (ver abajo).")
print()

df = pd.read_csv(csv_path)
y_true = df["label"].map(LABEL_MAP)
X = df.drop(columns=["label"])
y_pred = [r.attack_type for r in det.predict(X)]

labels = ["Normal", "DoS", "DDoS"]
print(f"  Exactitud global: {accuracy_score(y_true, y_pred):.4f}\n")
print("  Matriz de confusion (filas=real, columnas=predicho):")
print("  Orden:", labels)
print(confusion_matrix(y_true, y_pred, labels=labels))
print()
print(classification_report(y_true, y_pred, labels=labels,
                            target_names=labels, zero_division=0))
