"""Servidor del detector. Corre en el venv 3.11.
  python serve_detector.py
Escucha en 127.0.0.1:9999, recibe un JSON con las features por línea
y devuelve un JSON con el veredicto.
"""
import json
import socketserver

from src.detector import Detector

det = Detector.load("models/")
print("[detector] modelo cargado. features:", det.feature_names)
print("[detector] escuchando en 127.0.0.1:9999")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            raw = raw.strip()
            if not raw:
                continue
            try:
                feats = json.loads(raw)
                r = det.predict(feats)
                self.wfile.write((json.dumps(r.to_dict()) + "\n").encode())
            except Exception as e:
                self.wfile.write((json.dumps({"error": str(e)}) + "\n").encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


with Server(("127.0.0.1", 9999), Handler) as srv:
    srv.serve_forever()
