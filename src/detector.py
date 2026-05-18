"""Interfaz pública del detector de DDoS.

Esta clase es la única dependencia que la Ryu app del subgrupo B necesita
importar. Mantener la firma estable (ver docs/INTERFACE.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class DetectionResult:
    is_anomaly: bool
    attack_type: str
    confidence: float


class Detector:
    """Wrapper sobre el detector de anomalías + clasificador.

    Pendiente de implementar tras la Fase 2 y 3.
    """

    def __init__(self, anomaly_model, classifier, threshold: float) -> None:
        self.anomaly_model = anomaly_model
        self.classifier = classifier
        self.threshold = threshold

    @classmethod
    def load(cls, models_dir: str | Path) -> "Detector":
        raise NotImplementedError("Se implementa en la Fase 2/3.")

    def predict(self, features) -> DetectionResult:
        raise NotImplementedError("Se implementa en la Fase 2/3.")
