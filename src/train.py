"""Pipeline de entrenamiento end-to-end.

Reproduce lo que hacen los notebooks 03 y 04 pero sin gráficos, para
poder regenerar todos los modelos en una sola llamada:

    python -m src.train

Produce en `models/`: scaler.pkl, iforest.pkl, autoencoder.pt,
xgb_classifier.pkl, label_encoder.pkl, detector_meta.pkl.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.data import get_insdn_path
from src.detector import Autoencoder
from src.features import INSDN_TO_OPENFLOW, clean_insdn

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
RANDOM_STATE = 42
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


def _load_dataset() -> tuple[pd.DataFrame, pd.Series]:
    csv = next(get_insdn_path().rglob("*.csv"))
    df = pd.read_csv(csv, low_memory=False)
    df.columns = df.columns.str.strip()
    df = clean_insdn(df)
    X = df[list(INSDN_TO_OPENFLOW.keys())].copy()
    X["Flow Duration"] = X["Flow Duration"] / 1e6
    X = X.rename(columns=INSDN_TO_OPENFLOW)
    return X, df["Label"]


def _train_autoencoder(X_train_s: np.ndarray, epochs: int = 30) -> Autoencoder:
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


def main() -> None:
    MODELS_DIR.mkdir(exist_ok=True)
    print(f"Device: {DEVICE}")

    X, y_str = _load_dataset()
    feature_names = list(X.columns)
    print(f"Dataset: {X.shape}  clases={dict(y_str.value_counts())}")

    # --- Detector de anomalías: solo tráfico Normal ---
    is_normal = (y_str == "Normal").values
    X_norm, X_atk = X[is_normal], X[~is_normal]
    X_train, X_val_normal = train_test_split(X_norm, test_size=0.3, random_state=RANDOM_STATE)

    scaler = StandardScaler().fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_val_s = scaler.transform(X_val_normal)

    print("Entrenando Isolation Forest...")
    iforest = IsolationForest(
        n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1,
    ).fit(X_train_s)

    print("Entrenando Autoencoder...")
    ae = _train_autoencoder(X_train_s, epochs=30)

    ae_scores_val = _reconstruction_error(ae, X_val_s)
    if_scores_val = -iforest.score_samples(X_val_s)
    ae_thr_p99 = float(np.percentile(ae_scores_val, 99))
    if_thr_p99 = float(np.percentile(if_scores_val, 99))
    print(f"  AE threshold P99 = {ae_thr_p99:.5f}")
    print(f"  IF threshold P99 = {if_thr_p99:.5f}")

    # --- Clasificador: todas las clases menos U2R ---
    print("Entrenando clasificador XGBoost...")
    mask = y_str != "U2R"
    Xc = X[mask].reset_index(drop=True)
    yc_str = y_str[mask].reset_index(drop=True)
    le = LabelEncoder().fit(yc_str)
    yc = le.transform(yc_str)

    Xc_tr, Xc_te, yc_tr, yc_te = train_test_split(
        Xc, yc, test_size=0.2, stratify=yc, random_state=RANDOM_STATE,
    )
    counts = np.bincount(yc_tr)
    sample_weight = (len(yc_tr) / (len(counts) * counts))[yc_tr]

    clf = xgb.XGBClassifier(
        n_estimators=300, max_depth=8, learning_rate=0.1,
        objective="multi:softprob", num_class=len(le.classes_),
        tree_method="hist", n_jobs=-1, random_state=RANDOM_STATE,
        eval_metric="mlogloss",
    )
    clf.fit(Xc_tr, yc_tr, sample_weight=sample_weight)
    from sklearn.metrics import f1_score
    yp = clf.predict(Xc_te)
    print(f"  XGB F1 macro = {f1_score(yc_te, yp, average='macro'):.4f}")

    # --- Persistencia ---
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(iforest, MODELS_DIR / "iforest.pkl")
    torch.save(ae.state_dict(), MODELS_DIR / "autoencoder.pt")
    joblib.dump(clf, MODELS_DIR / "xgb_classifier.pkl")
    joblib.dump(le, MODELS_DIR / "label_encoder.pkl")
    joblib.dump({
        "features": feature_names,
        "ae_thr_p99": ae_thr_p99,
        "iforest_thr_p99": if_thr_p99,
        "ae_arch": {"in_dim": X.shape[1], "hidden": [16, 8, 4]},
    }, MODELS_DIR / "detector_meta.pkl")
    print(f"Modelos guardados en {MODELS_DIR}")


if __name__ == "__main__":
    main()
