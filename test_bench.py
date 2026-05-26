"""Banco de pruebas del detector entrenado.

Ejecutar en el venv 3.11, desde la raíz del repo:
    python test_bench.py

Tres partes:
  1) Casos canónicos: vectores de features representativos de cada situación,
     con el resultado esperado (PASS/FAIL). Incluye el caso del iperf de alto
     volumen, que antes daba falso positivo (prueba de regresión).
  2) Evaluación sobre un CSV completo: usa data/test.csv si existe (datos
     INDEPENDIENTES, lo ideal); si no, data/dataset.csv (sanity check sobre los
     datos de entrenamiento). Imprime exactitud y matriz de confusión.
  3) Lógica de mitigación de detect_app.py: stubbea Ryu para poder importar
     la Ryu app desde este venv y verifica que las reglas OpenFlow instaladas
     ante un DoS o un DDoS son las correctas (drop por IP / drop por MAC),
     que se respetan los umbrales de confianza y persistencia, y que las
     mitigaciones vencidas se limpian.
"""
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from src.detector import LABEL_MAP, Detector

ROOT = Path(__file__).resolve().parent

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


# Tupla: (descripción, features, ¿es ataque?, tipo esperado).
# Cada caso tiene encima un comentario con la estructura:
#   Escenario : qué pasa en la red en ese caso.
#   Señales   : valores característicos de las features clave.
#   Esperado  : qué debe devolver el detector (is_anomaly, attack_type).
#   Comprueba : qué propiedad del modelo se ejercita al pasar/fallar.
#
# Recordatorio del patrón src/dst:
#   normal punto-a-punto: src/dst ambos bajos (1-3 IPs)
#   DoS:                  1 IP origen → 1+ víctimas (src bajo)
#   DDoS:                 muchas IPs origen → 1+ víctimas (src alto)
#   pingall (benigno):    malla (src alto, dst alto, tasa MUY baja)
#
# Valores extraídos de muestras reales del dataset capturado.
CASES = [
    # ---------- NORMAL ----------

    # Caso 1 — Tráfico de fondo: ICMP a baja tasa entre 3 hosts en reposo.
    #   Escenario : red en estado idle, solo ping de diagnóstico.
    #   Señales   : pps=1, avg_size=98 B (ICMP), entropías bajas, new_flows=0.
    #   Esperado  : is_anomaly=False, tipo=Normal.
    #   Comprueba : el AE no flagea tráfico que ha visto durante el entreno.
    ("Normal: ping idle (ICMP a 1 pkt/s)",
     case(0, 0, 1, 1, 98, 98, 5.0,
          src_ent=1.5, dport_ent=0.0, dst_ent=1.5,
          new_flows=0.0, n_src=3, n_dst=3), False, "Normal"),

    # Caso 2 — Navegación HTTP normal con varios clientes activos.
    #   Escenario : 5 hosts cargando páginas (puerto 8000), tasa moderada.
    #   Señales   : pps=30, paquetes pequeños mezclados, new_flows bajo.
    #   Esperado  : is_anomaly=False, tipo=Normal.
    #   Comprueba : volumen + diversidad moderada no se confunden con ataque.
    ("Normal: HTTP browsing (varios clientes, tasa baja)",
     case(0, 8000, 6, 30, 2028, 67.6, 1.6,
          src_ent=2.25, dport_ent=2.5, dst_ent=2.25,
          new_flows=4.0, n_src=5, n_dst=5), False, "Normal"),

    # Caso 3 — REGRESIÓN: descarga grande establecida (estilo iperf).
    #   Escenario : 1 cliente bajando un fichero pesado a tasa alta.
    #   Señales   : pps=5000 y bytes/s ALTÍSIMOS, pero new_flows=0
    #               (conexión ya establecida, no hay handshakes nuevos).
    #   Esperado  : is_anomaly=False, tipo=Normal.
    #   Comprueba : el modelo separa "alto volumen + conexión establecida"
    #               (descarga) de "alto volumen + new_flows alto" (SYN flood).
    #               ESTE caso es el único que aún falla (sub-rate de Mininet
    #               en captura) — limitación documentada en docs/Summary.md.
    ("Normal: descarga grande establecida (1 IP, alto vol, new_flows=0) [REGRESION]",
     case(0, 8000, 6, 5000, 7500000, 1500, 30.0,
          src_ent=1.0, dport_ent=0.0, dst_ent=1.0,
          new_flows=0.0, n_src=2, n_dst=2), False, "Normal"),

    # Caso 4 — REGRESIÓN: pingall benigno (malla diagnóstica).
    #   Escenario : `mininet> pingall` — todos contra todos, tasa MUY baja.
    #   Señales   : n_src=8, n_dst=8, entropías altas... PERO pps=0.5.
    #   Esperado  : is_anomaly=False, tipo=Normal.
    #   Comprueba : "muchos a muchos" con tasa baja no se clasifica como
    #               multi-target DDoS — la tasa es el discriminador.
    ("Normal: pingall malla benigno (caso límite) [REGRESION]",
     case(0, 0, 1, 0.5, 49, 98, 3.0,
          src_ent=3.0, dport_ent=0.0, dst_ent=3.0,
          new_flows=20.0, n_src=8, n_dst=8), False, "Normal"),

    # ---------- DoS ----------

    # Caso 5 — ICMP flood desde 1 host.
    #   Escenario : `hping3 --icmp --faster` contra 1 víctima.
    #   Señales   : protocolo=1 (ICMP), pps=2500, avg_size=42 B, n_src=2.
    #   Esperado  : is_anomaly=True, tipo=DoS.
    #   Comprueba : detección de flood ICMP clásico.
    ("DoS: ICMP flood (42B, alta tasa, 1 fuente)",
     case(0, 0, 1, 2500, 105000, 42, 25.0,
          src_ent=0.0, dport_ent=1.5, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),

    # Caso 6 — SYN flood clásico con src_port aleatorio.
    #   Escenario : `hping3 -S --faster -p 80` (puerto origen rotando).
    #   Señales   : protocolo=6, avg_size=54 B (SYN sin payload), new_flows muy alto
    #               porque cada paquete genera un flujo nuevo.
    #   Esperado  : is_anomaly=True, tipo=DoS.
    #   Comprueba : new_flows_per_sec disparado distingue SYN flood de descarga.
    ("DoS: SYN flood clásico (54B, src_port aleatorio)",
     case(0, 80, 6, 2000, 108000, 54, 5.0,
          src_ent=0.0, dport_ent=9.0, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),

    # Caso 7 — ADVERSARIAL: SYN flood con padding hasta MTU completo.
    #   Escenario : `hping3 -S -d 1460 --faster` — el atacante intenta evadir
    #               la detección por tamaño metiendo payload basura en cada SYN.
    #   Señales   : avg_size=1514 B (parecido a descarga), PERO new_flows sigue alto.
    #   Esperado  : is_anomaly=True, tipo=DoS.
    #   Comprueba : el padding NO evade la detección; new_flows hace el trabajo.
    ("DoS: SYN flood PADDED 1500B (evade avg_packet_size) [ADVERSARIAL]",
     case(0, 80, 6, 695, 1052987, 1514, 1.2,
          src_ent=0.018, dport_ent=9.19, dst_ent=0.018,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),

    # Caso 8 — ACK flood.
    #   Escenario : `hping3 -A --faster -p 80` (ACKs sin handshake previo).
    #   Señales   : igual que SYN flood en tamaño y tasa.
    #   Esperado  : is_anomaly=True, tipo=DoS.
    #   Comprueba : la variante de flag TCP no importa; mismas señales = mismo veredicto.
    ("DoS: ACK flood (paquetes pequeños sin SYN)",
     case(0, 80, 6, 2000, 108000, 54, 10.0,
          src_ent=0.0, dport_ent=9.0, dst_ent=0.0,
          new_flows=292.0, n_src=2, n_dst=2), True, "DoS"),

    # Caso 9 — UDP flood al puerto DNS.
    #   Escenario : `hping3 --udp -p 53` con payload moderado.
    #   Señales   : protocolo=17, avg_size=140 B, new_flows menor (UDP no genera return).
    #   Esperado  : is_anomaly=True, tipo=DoS.
    #   Comprueba : el modelo no depende solo de new_flows; pps alto + 1 fuente basta.
    ("DoS: UDP flood (puerto 53, payload 100B)",
     case(0, 53, 17, 2000, 280000, 140, 15.0,
          src_ent=0.0, dport_ent=0.0, dst_ent=0.0,
          new_flows=20.0, n_src=2, n_dst=2), True, "DoS"),

    # Caso 10 — DoS multi-target.
    #   Escenario : 1 atacante apuntando a 3 víctimas distintas a la vez.
    #   Señales   : n_src=4 (atacante + 3 víctimas con tráfico de fondo), n_dst=4.
    #               src_ip_entropy baja porque el atacante domina los flujos.
    #   Esperado  : is_anomaly=True, tipo=DoS (1 fuente real, varias víctimas).
    #   Comprueba : multi-target NO se confunde con DDoS (que tendría src diverso).
    ("DoS: multi-target (1 atacante → 3 víctimas)",
     case(0, 80, 6, 542, 29295, 54, 4.2,
          src_ent=1.62, dport_ent=7.65, dst_ent=0.05,
          new_flows=292.0, n_src=4, n_dst=4), True, "DoS"),

    # ---------- DDoS ----------

    # Caso 11 — DDoS spoofeado (caso extremo de entropía).
    #   Escenario : `hping3 --rand-source -S` → IPs origen completamente random.
    #   Señales   : src_ip_entropy=8.36, n_src=328 (cada SYN parece de IP distinta).
    #   Esperado  : is_anomaly=True, tipo=DDoS.
    #   Comprueba : entropía extrema dispara el AE y XGBoost clasifica correctamente.
    ("DDoS: spoofeado (--rand-source, entropía extrema)",
     case(0, 80, 6, 1.0, 60, 60, 12.8,
          src_ent=8.36, dport_ent=0.0, dst_ent=0.0,
          new_flows=164.0, n_src=328, n_dst=1), True, "DDoS"),

    # Caso 12 — DDoS desde 6 hosts reales (sin spoofing).
    #   Escenario : 6 atacantes Mininet floodeando coordinadamente.
    #   Señales   : src_ip_entropy=1.07 (moderada, no extrema), n_src=6.
    #   Esperado  : is_anomaly=True, tipo=DDoS.
    #   Comprueba : el modelo detecta DDoS realista (entropía moderada),
    #               no solo el caso degenerado del spoofing.
    ("DDoS: 6 atacantes reales (entropía moderada)",
     case(0, 80, 6, 230, 12420, 54, 1.8,
          src_ent=1.07, dport_ent=7.23, dst_ent=2.05,
          new_flows=292.0, n_src=6, n_dst=6), True, "DDoS"),

    # Caso 13 — DDoS multi-target (N atacantes → M víctimas).
    #   Escenario : 4 atacantes contra 2 víctimas (red parcialmente comprometida).
    #   Señales   : n_src=7, n_dst=6, dst_ent=1.68 (varias víctimas).
    #   Esperado  : is_anomaly=True, tipo=DDoS.
    #   Comprueba : el cuadrante "src div alto + dst div alto + tasa alta" se
    #               separa correctamente del pingall (mismo patrón con tasa baja).
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
# Escenario : se pasan miles de filas reales (capturadas con capture_app.py)
#             por el detector en batch. Es la prueba de "performance global"
#             frente a las 13 sondas puntuales de Parte 1.
# Entrada   : data/test.csv si existe (split independiente, lo ideal) o, en
#             su defecto, data/dataset.csv (los MISMOS datos del entreno —
#             sanity check, no test real).
# Acción    : Detector.predict(DataFrame) sobre todo el CSV de una pasada.
# Esperado  : accuracy alta (~0.99+) y diagonal limpia en la matriz de
#             confusión. Si el F1 macro cae <0.95, hay un escenario
#             contaminado en el dataset o el entreno se ha torcido.
# Verifica  : que el modelo generaliza al conjunto completo, no solo a los
#             casos canónicos cocinados a mano.
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
print("=" * 70)


# ---------------------------------------------------------------------------
# Parte 3 — Logica de mitigacion (detect_app.py)
# ---------------------------------------------------------------------------
# detect_app vive en otro Python (el del sistema, con Ryu). Para poder
# importarlo desde este venv le ponemos stubs minimos de ryu.* en sys.modules
# y construimos un DetectApp saltando su __init__ (que llama a hub.spawn,
# se conecta a Influx, etc.). Despues invocamos directamente _block_ip,
# _block_mac, _mitigate y _prune_blocks con un datapath ficticio que registra
# cada send_msg como una tupla ("FlowMod", kwargs).

print("PARTE 3 - Logica de mitigacion\n")

import sys
import time
import types
from unittest.mock import MagicMock


def _install_ryu_stubs():
    class _RyuApp:
        OFP_VERSIONS = []
        def __init__(self, *a, **kw): pass

    def _noop_decorator(*args, **kwargs):
        return lambda f: f

    # Modulos "bolsa de atributos" (ofp_event, ofproto_v1_3, ether_types...)
    # los stubeamos con MagicMock para que cualquier atributo que detect_app
    # consulte exista sin tener que enumerarlos uno a uno.
    for name in ("ryu", "ryu.base", "ryu.controller", "ryu.lib", "ryu.ofproto"):
        sys.modules[name] = types.ModuleType(name)

    sys.modules["ryu.base.app_manager"] = types.ModuleType("ryu.base.app_manager")
    sys.modules["ryu.base.app_manager"].RyuApp = _RyuApp
    sys.modules["ryu.base"].app_manager = sys.modules["ryu.base.app_manager"]

    sys.modules["ryu.controller.ofp_event"] = MagicMock()
    sys.modules["ryu.controller.handler"] = types.ModuleType("ryu.controller.handler")
    sys.modules["ryu.controller.handler"].CONFIG_DISPATCHER = 1
    sys.modules["ryu.controller.handler"].MAIN_DISPATCHER = 2
    sys.modules["ryu.controller.handler"].set_ev_cls = _noop_decorator

    sys.modules["ryu.lib.hub"] = types.ModuleType("ryu.lib.hub")
    sys.modules["ryu.lib.hub"].spawn = lambda *a, **kw: None
    sys.modules["ryu.lib.hub"].sleep = lambda *a, **kw: None

    sys.modules["ryu.lib.packet"] = MagicMock()
    sys.modules["ryu.ofproto.ofproto_v1_3"] = MagicMock(OFP_VERSION=4)
    sys.modules["influxdb"] = MagicMock()


_install_ryu_stubs()
sys.path.insert(0, str(ROOT))
sys.modules.pop("detect_app", None)
import detect_app  # noqa: E402


def _make_app():
    """DetectApp sin pasar por el __init__ de Ryu."""
    app = detect_app.DetectApp.__new__(detect_app.DetectApp)
    app.mac_to_port = {}
    app.ip_to_mac = {}
    app.datapaths = {}
    app.prev = {}
    app.prev_keys = set()
    app.attack_streak = 0
    app.in_attack = False
    app.mitigated = set()
    app.influx = None
    app.logger = MagicMock()
    return app


def _make_dp():
    """Datapath ficticio: registra cada send_msg como ('FlowMod', kwargs)."""
    dp = MagicMock()
    dp.sent = []
    dp.ofproto_parser.OFPFlowMod = lambda **kw: ("FlowMod", kw)
    dp.ofproto_parser.OFPMatch = lambda **kw: ("Match", kw)
    dp.send_msg = lambda msg: dp.sent.append(msg)
    return dp


def _flow_stat(ip_src):
    stat = MagicMock()
    stat.match = {"ipv4_src": ip_src}
    return stat


MIT_TIMEOUT = detect_app.MIT_TIMEOUT
mit_tests = []


def _case(name):
    def wrap(fn):
        mit_tests.append((name, fn))
        return fn
    return wrap


@_case("_block_ip instala OFPFlowMod con ipv4_src + drop + hard_timeout")
def _t1():
    """
    Escenario : detectamos un DoS desde 10.0.0.5 y llamamos a _block_ip.
    Acción    : _block_ip(dp, '10.0.0.5').
    Esperado  : se envía UNA OFPFlowMod al switch con match.ipv4_src=10.0.0.5,
                acción vacía (=drop), hard_timeout=MIT_TIMEOUT, prioridad 100.
    Verifica  : la mitigación de DoS instala la regla correcta a nivel L3.
    """
    app, dp = _make_app(), _make_dp()
    app._block_ip(dp, "10.0.0.5")
    assert len(dp.sent) == 1
    _, kw = dp.sent[0]
    _, match_kw = kw["match"]
    assert match_kw["ipv4_src"] == "10.0.0.5"
    assert kw["hard_timeout"] == MIT_TIMEOUT
    assert kw["instructions"] == []
    assert kw["priority"] == 100


@_case("_block_mac instala OFPFlowMod con eth_src + drop + hard_timeout")
def _t2():
    """
    Escenario : detectamos un DDoS desde un host con MAC aa:bb:cc:dd:ee:ff.
    Acción    : _block_mac(dp, 'aa:bb:cc:dd:ee:ff').
    Esperado  : una OFPFlowMod con match.eth_src=<MAC>, drop, timeout, prio 100.
    Verifica  : la mitigación de DDoS opera en L2 (es el cambio principal del
                último PR: aprovechamos que el controlador SDN ve la MAC).
    """
    app, dp = _make_app(), _make_dp()
    app._block_mac(dp, "aa:bb:cc:dd:ee:ff")
    assert len(dp.sent) == 1
    _, kw = dp.sent[0]
    _, match_kw = kw["match"]
    assert match_kw["eth_src"] == "aa:bb:cc:dd:ee:ff"
    assert kw["hard_timeout"] == MIT_TIMEOUT
    assert kw["instructions"] == []
    assert kw["priority"] == 100


@_case("_mitigate ignora flujos con confidence < MIT_MIN_CONF")
def _t3():
    """
    Escenario : el detector marca un flujo como DoS pero con confianza 0.5
                (por debajo del umbral MIT_MIN_CONF=0.80).
    Acción    : _mitigate con ese veredicto.
    Esperado  : NO se envía ninguna regla, self.mitigated sigue vacío.
    Verifica  : la salvaguarda de confianza previene mitigaciones precipitadas
                cuando el clasificador no está seguro (típico de falsos
                positivos del AE que XGBoost rescata "a duras penas").
    """
    app, dp = _make_app(), _make_dp()
    pairs = [(_flow_stat("10.0.0.5"),
              {"is_anomaly": True, "attack_type": "DoS", "confidence": 0.5})]
    app._mitigate(dp, pairs)
    assert dp.sent == []
    assert app.mitigated == set()


@_case("_mitigate ignora veredictos con is_anomaly=False")
def _t4():
    """
    Escenario : flujo legítimo (is_anomaly=False) con alta confianza.
    Acción    : _mitigate con ese veredicto.
    Esperado  : NO se hace nada (no se mitiga lo que no es ataque).
    Verifica  : el filtro is_anomaly funciona — no basta con que el flujo
                llegue a _mitigate; tiene que estar marcado como anómalo.
    """
    app, dp = _make_app(), _make_dp()
    pairs = [(_flow_stat("10.0.0.5"),
              {"is_anomaly": False, "attack_type": "Normal", "confidence": 0.99})]
    app._mitigate(dp, pairs)
    assert dp.sent == []
    assert app.mitigated == set()


@_case("_mitigate DoS bloquea IP origen y registra clave ('ip', ip)")
def _t5():
    """
    Escenario : flujo desde 10.0.0.5 clasificado como DoS, confianza 0.95.
    Acción    : _mitigate con ese par (stat, veredicto).
    Esperado  : llama a _block_ip internamente → envía OFPFlowMod con
                ipv4_src=10.0.0.5, y registra ('ip','10.0.0.5') en self.mitigated
                con su instante de expiración.
    Verifica  : el camino end-to-end DoS (decisión → regla → registro)
                funciona y los datos pasan por las claves correctas.
    """
    app, dp = _make_app(), _make_dp()
    pairs = [(_flow_stat("10.0.0.5"),
              {"is_anomaly": True, "attack_type": "DoS", "confidence": 0.95})]
    app._mitigate(dp, pairs)
    assert len(dp.sent) == 1
    _, kw = dp.sent[0]
    _, match_kw = kw["match"]
    assert match_kw["ipv4_src"] == "10.0.0.5"
    assert ("ip", "10.0.0.5") in app.mitigated


@_case("_mitigate DDoS resuelve IP->MAC y bloquea por eth_src")
def _t6():
    """
    Escenario : el detector marca DDoS desde 10.0.0.6, conocido en el mapa
                ip_to_mac como aa:bb:cc:00:00:06 (sembrado en packet_in).
    Acción    : _mitigate con ese veredicto.
    Esperado  : llama a _block_mac con la MAC resuelta → OFPFlowMod con
                eth_src=<MAC>; registra ('mac', <MAC>) en self.mitigated.
    Verifica  : la resolución IP→MAC y la mitigación L2 funcionan en conjunto
                (este es el punto clave de la nueva política DDoS).
    """
    app, dp = _make_app(), _make_dp()
    app.ip_to_mac["10.0.0.6"] = "aa:bb:cc:00:00:06"
    pairs = [(_flow_stat("10.0.0.6"),
              {"is_anomaly": True, "attack_type": "DDoS", "confidence": 0.95})]
    app._mitigate(dp, pairs)
    assert len(dp.sent) == 1
    _, kw = dp.sent[0]
    _, match_kw = kw["match"]
    assert match_kw["eth_src"] == "aa:bb:cc:00:00:06"
    assert ("mac", "aa:bb:cc:00:00:06") in app.mitigated


@_case("_mitigate DDoS sin MAC conocida no actua (avisa por log)")
def _t7():
    """
    Escenario : DDoS desde 10.0.0.7 PERO ip_to_mac está vacío (caso raro:
                detectamos el ataque por flow_stats antes de haber visto un
                packet_in de esa IP, p.ej. ataque ya en curso al arrancar Ryu).
    Acción    : _mitigate con ese veredicto.
    Esperado  : NO se envía regla; self.logger.warning es invocado para dejar
                rastro en el log; self.mitigated sigue vacío.
    Verifica  : el caso degenerado se degrada con elegancia — no se intenta
                instalar una regla con eth_src=None ni crashea la app.
    """
    app, dp = _make_app(), _make_dp()
    # ip_to_mac vacio a proposito
    pairs = [(_flow_stat("10.0.0.7"),
              {"is_anomaly": True, "attack_type": "DDoS", "confidence": 0.95})]
    app._mitigate(dp, pairs)
    assert dp.sent == []
    assert app.mitigated == set()
    app.logger.warning.assert_called()


@_case("_mitigate deduplica si la mitigacion sigue activa")
def _t8():
    """
    Escenario : el ataque persiste a lo largo de varios sondeos (cosa normal:
                cada 2s vuelve a llegar otro batch con el mismo atacante).
    Acción    : _mitigate dos veces seguidas con el mismo veredicto, dentro
                del MIT_TIMEOUT de la primera.
    Esperado  : la SEGUNDA llamada no instala una nueva regla — _recent()
                detecta que ya hay una mitigación activa para esa clave.
    Verifica  : evita inundar el switch con OFPFlowMod duplicados cuando
                un ataque tarda más que un sondeo en parar.
    """
    app, dp = _make_app(), _make_dp()
    pairs = [(_flow_stat("10.0.0.5"),
              {"is_anomaly": True, "attack_type": "DoS", "confidence": 0.95})]
    app._mitigate(dp, pairs)        # primera vez -> bloquea
    app._mitigate(dp, pairs)        # segunda vez dentro del timeout
    assert len(dp.sent) == 1        # no se duplica


@_case("_flow_removed_handler limpia self.mitigated al expirar el bloqueo en OVS")
def _t9():
    """
    Escenario : OVS expira una regla de bloqueo (prio=100) por hard_timeout y
                envía EventOFPFlowRemoved al controlador. Hay dos bloqueos en
                self.mitigated: uno para el flujo que expira y otro intacto.
    Acción    : _flow_removed_handler con un msg de prio=100 cuyo match contiene
                la ipv4_src del bloqueo expirado (caso DoS).
    Esperado  : la entrada ('ip', <ip>) desaparece de self.mitigated; la otra
                permanece. Esto deja paso a futuras mitigaciones del mismo target.
    Verifica  : el ciclo de vida de las mitigaciones queda atado a la verdad
                de OVS — no a una estimación basada en time.time() en Python.
                Sustituye al antiguo _prune_blocks que vivía de timestamps.
    """
    app = _make_app()
    app.mitigated.add(("ip", "10.0.0.8"))
    app.mitigated.add(("mac", "aa:bb:cc:00:00:09"))

    # Fingimos el evento que enviaría OVS al expirar la regla de bloqueo de 10.0.0.8.
    ev = MagicMock()
    ev.msg.priority = 100
    ev.msg.match = {"ipv4_src": "10.0.0.8"}
    app._flow_removed_handler(ev)

    assert ("ip", "10.0.0.8") not in app.mitigated
    assert ("mac", "aa:bb:cc:00:00:09") in app.mitigated


passed_mit = 0
for name, fn in mit_tests:
    try:
        fn()
        passed_mit += 1
        print(f"  [PASS] {name}")
    except AssertionError as e:
        print(f"  [FAIL] {name}")
        if str(e):
            print(f"         {e}")
    except Exception as e:
        print(f"  [ERR ] {name}")
        print(f"         {type(e).__name__}: {e}")

print(f"\n  -> Mitigacion: {passed_mit}/{len(mit_tests)} casos OK")
