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
         src_ent, dport_ent, new_flows, n_src):
    return {
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "packets_per_sec": pps, "bytes_per_sec": bps, "avg_packet_size": avg_size,
        "flow_duration_sec": age, "src_ip_entropy": src_ent,
        "dst_port_entropy": dport_ent, "new_flows_per_sec": new_flows,
        "num_distinct_src_ips": n_src,
    }


# (descripción, features, ¿es ataque?, tipo esperado)
CASES = [
    ("ping normal (ICMP, bajo volumen)",
     case(0, 0, 1, 5, 490, 98, 5.0, 1.0, 0.0, 0.0, 2), False, "Normal"),
    ("iperf TCP (alto volumen, paquetes grandes) [REGRESION]",
     case(0, 5001, 6, 51841, 2411967599, 46525, 3.0, 1.0, 1.5, 0.0, 2), False, "Normal"),
    ("iperf UDP (alto volumen)",
     case(0, 5001, 17, 9000, 13000000, 1470, 3.0, 1.0, 1.5, 0.0, 3), False, "Normal"),
    ("DoS ICMP flood (1 fuente)",
     case(0, 0, 1, 2922, 122724, 42, 25.0, 1.0, 1.5, 0.0, 2), True, "DoS"),
    ("DoS SYN flood (1 fuente)",
     case(0, 80, 6, 4000, 240000, 60, 5.0, 1.0, 0.0, 0.0, 2), True, "DoS"),
    ("DDoS spoofeado (muchas fuentes)",
     case(0, 80, 6, 1.0, 60, 60, 12.8, 8.36, 0.0, 164.0, 328), True, "DDoS"),
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
