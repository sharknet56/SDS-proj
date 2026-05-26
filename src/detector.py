"""Interfaz pública del detector de DDoS.

La Ryu app del subgrupo B importa solo desde aquí:

    from src.detector import Detector
    det = Detector.load("models/")
    result = det.predict(features_dict)            # umbral estático P99
    # o, para integrar un umbral dinámico calculado en la app:
    result = det.predict(features_dict, threshold=dyn_thr)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

# Normaliza las etiquetas del CSV a la forma canónica. "Normal" (con mayúscula)
# es importante porque Detector.predict decide is_anomaly comparando con "Normal".
LABEL_MAP = {"normal": "Normal", "dos": "DoS", "ddos": "DDoS"}


class Autoencoder(nn.Module):
    """Misma arquitectura usada en `notebooks/03_anomaly_detector.ipynb`.

    Mantener la definición en sincronía con la del notebook. Si se cambia
    la arquitectura, hay que reentrenar y volver a guardar.
    """

    def __init__(self, in_dim: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_dim, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
            nn.Linear(8, 4),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 8), nn.ReLU(),
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, in_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


@dataclass
class DetectionResult:
    is_anomaly: bool
    attack_type: str
    confidence: float
    anomaly_score: float

    def to_dict(self) -> dict:
        return {
            "is_anomaly": self.is_anomaly,
            "attack_type": self.attack_type,
            "confidence": round(self.confidence, 4),
            "anomaly_score": round(self.anomaly_score, 6),
        }


class Detector:
    """Pipeline AE (anomalía) + XGBoost (tipo de ataque).

    Diseñado para que la Ryu app cargue una vez (`Detector.load`) y llame
    a `predict` por cada flow en cada poll.
    """

    def __init__(
        self,
        scaler,
        autoencoder: Autoencoder,
        classifier,
        label_encoder,
        feature_names: list[str],
        default_threshold: float,
    ) -> None:
        self.scaler = scaler
        self.ae = autoencoder
        self.classifier = classifier
        self.label_encoder = label_encoder
        self.feature_names = feature_names
        self.default_threshold = default_threshold
        self._normal_idx = int(np.where(label_encoder.classes_ == "Normal")[0][0])
        self.ae.eval()

    # ---------- factory ----------
    @classmethod
    def load(cls, models_dir: str | Path) -> "Detector":
        models_dir = Path(models_dir)
        meta = joblib.load(models_dir / "detector_meta.pkl")
        scaler = joblib.load(models_dir / "scaler.pkl")
        classifier = joblib.load(models_dir / "xgb_classifier.pkl")
        label_encoder = joblib.load(models_dir / "label_encoder.pkl")

        ae = Autoencoder(in_dim=meta["ae_arch"]["in_dim"])
        ae.load_state_dict(torch.load(models_dir / "autoencoder.pt", map_location="cpu"))
        return cls(
            scaler=scaler,
            autoencoder=ae,
            classifier=classifier,
            label_encoder=label_encoder,
            feature_names=meta["features"],
            default_threshold=meta["ae_thr_p99"],
        )

    # ---------- low-level ----------
    def score(self, features) -> np.ndarray:
        """Devuelve el error de reconstrucción del AE (score de anomalía)."""
        X_scaled = self._scaled_array(features)
        with torch.no_grad():
            xt = torch.tensor(X_scaled, dtype=torch.float32)
            return ((self.ae(xt) - xt) ** 2).mean(dim=1).numpy()

    def classify(self, features) -> tuple[np.ndarray, np.ndarray]:
        """Clasificador puro (sin filtro de anomalía).

        Devuelve (labels, max_proba). `labels` es array de strings.
        """
        df = self._to_dataframe(features)
        proba = self.classifier.predict_proba(df)
        idx = proba.argmax(axis=1)
        labels = self.label_encoder.inverse_transform(idx)
        return labels, proba[np.arange(len(idx)), idx]

    # ---------- API pública ----------
    def predict(
        self,
        features: Mapping | pd.DataFrame,
        threshold: float | None = None,
    ) -> DetectionResult | list[DetectionResult]:
        """Predicción end-to-end.

        - `features` puede ser un dict (un flow) o un DataFrame (varios).
        - `threshold` permite inyectar el umbral dinámico calculado en la
          Ryu app. Si es None, se usa el umbral estático P99 entrenado.

        Devuelve un `DetectionResult` o lista del mismo, según la entrada.
        """
        single = isinstance(features, Mapping)
        thr = self.default_threshold if threshold is None else threshold

        df = self._to_dataframe(features)
        scores = self.score(df)
        anomalous = scores > thr

        results: list[DetectionResult] = []
        # Para los anómalos, llamamos al clasificador; para los normales,
        # devolvemos "Normal" directamente sin gastar CPU.
        if anomalous.any():
            proba = self.classifier.predict_proba(df.iloc[anomalous])
            idx = proba.argmax(axis=1)
            labels = self.label_encoder.inverse_transform(idx)
            confs = proba[np.arange(len(idx)), idx]
        else:
            labels, confs = np.array([]), np.array([])

        anomalous_iter = iter(zip(labels, confs))
        for i, (s, is_anom) in enumerate(zip(scores, anomalous)):
            if is_anom:
                lbl, conf = next(anomalous_iter)
                results.append(DetectionResult(
                    is_anomaly=bool(lbl != "Normal"),
                    attack_type=str(lbl),
                    confidence=float(conf),
                    anomaly_score=float(s),
                ))
            else:
                results.append(DetectionResult(
                    is_anomaly=False,
                    attack_type="Normal",
                    confidence=1.0,
                    anomaly_score=float(s),
                ))

        return results[0] if single else results

    # ---------- helpers ----------
    def _to_dataframe(self, features) -> pd.DataFrame:
        if isinstance(features, Mapping):
            df = pd.DataFrame([features])
        elif isinstance(features, pd.DataFrame):
            df = features
        else:
            raise TypeError(f"features debe ser dict o DataFrame, no {type(features)}")

        missing = [c for c in self.feature_names if c not in df.columns]
        if missing:
            raise ValueError(f"Faltan features: {missing}. Esperadas: {self.feature_names}")
        return df[self.feature_names].astype(np.float32).reset_index(drop=True)

    def _scaled_array(self, features) -> np.ndarray:
        df = self._to_dataframe(features)
        return self.scaler.transform(df)
