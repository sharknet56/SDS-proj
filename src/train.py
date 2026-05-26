"""Entrenamiento del detector con el dataset PROPIO (data/dataset.csv).

    python -m src.train

Entrena tres modelos y compara dos enfoques de clasificación:

    data/dataset.csv  (11 features + label)
        │  limpieza de duplicados
        ▼
        ├─ ETAPA 1: AUTOENCODER  (no supervisado, solo tráfico Normal)
        │     11 → 16 → 8 → 4 → 8 → 16 → 11   → error de reconstrucción
        │     umbral = P99 del error sobre Normal       → ¿es un ataque?
        │
        ├─ ETAPA 2a: XGBoost MULTICLASE  {Normal, DoS, DDoS}   ← se GUARDA (producción)
        │     responde "¿de qué tipo?"; aprovecha las features agregadas
        │
        └─ ETAPA 2b: XGBoost BINARIO     {Normal, Attack}      ← solo COMPARACIÓN
              responde "¿ataque sí/no?"; fusiona DoS+DDoS en "Attack"

Para cada clasificador imprime F1 macro + matriz de confusión, de modo que se
pueda comparar el enfoque binario (objetivo declarado) con el multiclase (que
además distingue DoS de DDoS gracias a num_distinct_src_ips / src_ip_entropy).

Guarda en `models/`: scaler.pkl, autoencoder.pt, xgb_classifier.pkl (multiclase,
producción), label_encoder.pkl, xgb_classifier_binary.pkl, label_encoder_binary.pkl,
detector_meta.pkl.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.detector import Autoencoder

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
DATASET = ROOT / "data" / "dataset.csv"
RANDOM_STATE = 42
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Normaliza las etiquetas del CSV a una forma canónica. "Normal" (con mayúscula)
# es importante porque src/detector.py decide is_anomaly comparando con "Normal".
LABEL_MAP = {"normal": "Normal", "dos": "DoS", "ddos": "DDoS"}

DEDUP = True

# Percentil para el umbral del Autoencoder.
# Bajar a 95 = más sensible (menos falsos negativos, más falsos positivos).
# Subir a 99.5 = más conservador.
AE_THRESHOLD_PERCENTILE = 99


def _load_dataset() -> tuple[pd.DataFrame, pd.Series]:
    """Lee el CSV propio: todas las columnas son features salvo 'label'."""
    df = pd.read_csv(DATASET)
    df.columns = df.columns.str.strip()
    y = df["label"].map(LABEL_MAP)
    X = df.drop(columns=["label"]).astype("float32")
    return X, y


def _train_autoencoder(X_train_s: np.ndarray, epochs: int = 30) -> Autoencoder:
    """Entrena el autoencoder a reconstruir tráfico Normal (in_dim = nº de features)."""
    ae = Autoencoder(in_dim=X_train_s.shape[1]).to(DEVICE)
    opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
    X = torch.tensor(X_train_s, dtype=torch.float32, device=DEVICE)
    for epoch in range(epochs):
        ae.train()
        perm = torch.randperm(len(X))
        loss_acc = 0.0
        for i in range(0, len(perm), 512):
            idx = perm[i:i + 512]
            xb = X[idx]
            opt.zero_grad()
            loss = ((ae(xb) - xb) ** 2).mean()
            loss.backward()
            opt.step()
            loss_acc += loss.item() * len(idx)
        if (epoch + 1) % 5 == 0:
            print(f"  AE epoch {epoch + 1:2d}  loss={loss_acc / len(perm):.5f}")
    return ae


def _reconstruction_error(ae: Autoencoder, X: np.ndarray) -> np.ndarray:
    ae.eval()
    with torch.no_grad():
        xt = torch.tensor(X, dtype=torch.float32, device=DEVICE)
        return ((ae(xt) - xt) ** 2).mean(dim=1).cpu().numpy()


def _ae_diagnostic_report(
    ae: Autoencoder,
    X: pd.DataFrame,
    y: pd.Series,
    scaler,
    threshold: float,
) -> None:
    """Muestra el error de reconstrucción del AE por clase y la tasa de detección.

    Permite verificar si el umbral realmente separa tráfico normal de ataques.
    Una buena separación: Normal ≈ 0% detectado, DoS/DDoS ≈ 100% detectado.
    """
    X_s = scaler.transform(X)
    scores = _reconstruction_error(ae, X_s)
    print(f"\n=== Diagnóstico AE (umbral P{AE_THRESHOLD_PERCENTILE} = {threshold:.5f}) ===")
    print(f"  {'Clase':<8} {'n':>5}  {'p50':>9}  {'p99':>9}  {'max':>9}  {'detectado':>12}")
    for label in sorted(y.unique()):
        mask = (y == label).values
        s = scores[mask]
        detected = int((s > threshold).sum())
        print(
            f"  {label:<8} {len(s):>5}  {np.percentile(s,50):>9.5f}  "
            f"{np.percentile(s,99):>9.5f}  {s.max():>9.5f}  "
            f"{detected:>5}/{len(s)} ({100*detected/len(s):>5.1f}%)"
        )


def _train_and_eval(name: str, X: pd.DataFrame, y_str: pd.Series):
    """Entrena un XGBoost y muestra F1 macro + matriz de confusión."""
    le = LabelEncoder().fit(y_str)
    y = le.transform(y_str)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE,
    )
    # Pesos por clase: compensan el desbalanceo (mucho normal/ddos, poco dos).
    counts = np.bincount(ytr)
    sample_weight = (len(ytr) / (len(counts) * counts))[ytr]

    if len(le.classes_) == 2:
        clf = xgb.XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1,
            objective="binary:logistic",
            tree_method="hist", n_jobs=-1, random_state=RANDOM_STATE,
            eval_metric="logloss",
        )
    else:
        clf = xgb.XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1,
            objective="multi:softprob", num_class=len(le.classes_),
            tree_method="hist", n_jobs=-1, random_state=RANDOM_STATE,
            eval_metric="mlogloss",
        )
    clf.fit(Xtr, ytr, sample_weight=sample_weight)

    yp = clf.predict(Xte)
    print(f"\n=== {name} ===")
    print(f"  F1 macro = {f1_score(yte, yp, average='macro', labels=list(range(len(le.classes_)))):.4f}")
    print(f"  Clases: {list(le.classes_)}")
    print("  Matriz de confusión (filas=real, columnas=predicho):")
    all_labels = list(range(len(le.classes_)))
    print(confusion_matrix(yte, yp, labels=all_labels))
    print(classification_report(yte, yp, labels=all_labels, target_names=le.classes_, zero_division=0))
    return clf, le


def main() -> None:
    MODELS_DIR.mkdir(exist_ok=True)
    print(f"Device: {DEVICE}")

    X, y_str = _load_dataset()
    print(f"Dataset: {X.shape}  clases={dict(y_str.value_counts())}")

    if DEDUP:
        before = len(X)
        keep = ~X.duplicated(keep="first")
        X = X[keep].reset_index(drop=True)
        y_str = y_str[keep].reset_index(drop=True)
        print(f"Dedup: {before} -> {len(X)} filas "
              f"({before - len(X)} duplicados, {100 * (before - len(X)) / before:.1f}%)")

    feature_names = list(X.columns)
    print(f"Features ({len(feature_names)}): {feature_names}")

    # Filas donde el vector de features completo es todo ceros no aportan ninguna
    # señal — ni de tasa, ni de entropía, ni de tamaño de paquete.
    all_zero = (X == 0).all(axis=1)
    if all_zero.sum():
        print(f"Filtrando {all_zero.sum()} filas con vector de features completamente vacío")
        X = X[~all_zero].reset_index(drop=True)
        y_str = y_str[~all_zero].reset_index(drop=True)
        print(f"Dataset tras filtrado: {X.shape}  clases={dict(y_str.value_counts())}")

    # ---------- ETAPA 1: autoencoder (solo Normal) ----------
    is_normal = (y_str == "Normal").values
    X_norm = X[is_normal]
    X_train, X_val_normal = train_test_split(
        X_norm, test_size=0.3, random_state=RANDOM_STATE,
    )

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val_normal)

    print("\nEntrenando Autoencoder...")
    ae = _train_autoencoder(X_train_s, epochs=30)
    ae_scores_val = _reconstruction_error(ae, X_val_s)
    ae_thr_p99 = float(np.percentile(ae_scores_val, AE_THRESHOLD_PERCENTILE))
    print(f"  AE threshold P{AE_THRESHOLD_PERCENTILE} = {ae_thr_p99:.5f}")
    _ae_diagnostic_report(ae, X, y_str, scaler, ae_thr_p99)

    # ---------- ETAPA 2a: clasificador MULTICLASE (producción) ----------
    clf_multi, le_multi = _train_and_eval("MULTICLASE  {Normal, DoS, DDoS}", X, y_str)

    # ---------- ETAPA 2b: clasificador BINARIO (comparación) ----------
    y_bin = y_str.apply(lambda c: "Normal" if c == "Normal" else "Attack")
    clf_bin, le_bin = _train_and_eval("BINARIO  {Normal, Attack}", X, y_bin)

    # ---------- Persistencia ----------
    # El modelo de producción es el MULTICLASE: su salida ya da el binario
    # (is_anomaly = attack_type != 'Normal') y además el tipo de ataque.
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    torch.save(ae.state_dict(), MODELS_DIR / "autoencoder.pt")
    joblib.dump(clf_multi, MODELS_DIR / "xgb_classifier.pkl")
    joblib.dump(le_multi, MODELS_DIR / "label_encoder.pkl")
    joblib.dump(clf_bin, MODELS_DIR / "xgb_classifier_binary.pkl")
    joblib.dump(le_bin, MODELS_DIR / "label_encoder_binary.pkl")
    joblib.dump({
        "features": feature_names,
        "ae_thr_p99": ae_thr_p99,
        "ae_arch": {"in_dim": X.shape[1], "hidden": [16, 8, 4]},
    }, MODELS_DIR / "detector_meta.pkl")
    print(f"\nModelos guardados en {MODELS_DIR}")


if __name__ == "__main__":
    main()
