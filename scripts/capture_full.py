#!/usr/bin/env python3
"""Captura completa del dataset desde cero.

Definición operativa:

    Normal  : tráfico corporativo realista. Incluye **descarga pesada de una
              sola IP** (la prueba clave para que el modelo aprenda que volumen
              ≠ ataque cuando la conexión está establecida).
    DoS     : ataque de inundación desde una sola IP. Cubrimos las variantes
              principales (TCP SYN/ACK, ICMP, UDP) con distintas tasas y
              tamaños de paquete para que el modelo NO se ate a una firma única.
    DDoS    : ataque distribuido. Incluye spoofeado (--rand-source, entropía
              extrema) y atacantes reales (entropía moderada).

Diferencia crítica respecto a capturas anteriores:
  - NO usamos `-k -s <puerto>` en hping3 → el src_port queda aleatorio →
    cada SYN crea un flujo nuevo de retorno → `new_flows_per_sec` se dispara.
    Esta es la señal que distingue un flood de una descarga legítima.
  - Activamos CAPTURE_FILTER_IDLE=1 → se descartan flujos sin actividad en
    la ventana, evitando la explosión de 200 MB que tuvimos antes.

Uso:
    sudo python3 scripts/capture_full.py
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

_sudo_user = os.environ.get("SUDO_USER")
if _sudo_user and os.geteuid() == 0:
    import pwd
    _home = pwd.getpwnam(_sudo_user).pw_dir
    _pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    _user_site = f"{_home}/.local/lib/{_pyver}/site-packages"
    if os.path.isdir(_user_site) and _user_site not in sys.path:
        sys.path.insert(0, _user_site)

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.clean import cleanup as mn_cleanup

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "data" / "dataset.csv"
RYU_PORT = 6633
DURATION_S = 90


class StarTopo(Topo):
    """8 hosts conectados a un switch OpenFlow 1.3."""

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        for i in range(1, 9):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s1)


def start_ryu(label: str) -> subprocess.Popen:
    env = {**os.environ,
           "CAPTURE_LABEL": label,
           "CAPTURE_CSV": str(CSV_PATH),
           "CAPTURE_FILTER_IDLE": "1",
           "PYTHONPATH": str(ROOT)}
    p = subprocess.Popen(
        ["ryu-manager", "--ofp-tcp-listen-port", str(RYU_PORT),
         str(ROOT / "capture_app.py")],
        env=env, cwd=str(ROOT),
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    for _ in range(20):
        time.sleep(1)
        r = subprocess.run(["ss", "-ltn"], capture_output=True, text=True)
        if f":{RYU_PORT} " in r.stdout:
            return p
    p.kill()
    raise RuntimeError(f"ryu-manager no escucha en :{RYU_PORT}")


def stop_ryu(p: subprocess.Popen) -> None:
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def with_capture(label: str, scenario_fn, name: str) -> None:
    print(f"\n=== {name}  (label={label})  duration={DURATION_S}s ===", flush=True)
    ryu = start_ryu(label)
    net = Mininet(
        topo=StarTopo(),
        switch=OVSSwitch,
        controller=RemoteController("c0", ip="127.0.0.1", port=RYU_PORT),
        autoSetMacs=True,
    )
    net.start()
    time.sleep(3)
    try:
        scenario_fn(net)
    finally:
        for h in net.hosts:
            h.cmd(
                "pkill -9 -f hping3 2>/dev/null; "
                "pkill -9 ping 2>/dev/null; "
                "pkill -9 -f 'http.server' 2>/dev/null; "
                "pkill -9 curl 2>/dev/null; "
                "pkill -9 wget 2>/dev/null; true"
            )
        net.stop()
        stop_ryu(ryu)
        time.sleep(2)


# ============================================================
# NORMAL  — tráfico corporativo, conexiones establecidas
# ============================================================

def normal_idle(net):
    """Ping a 1 paquete/s. Baseline en reposo."""
    h1, h2, h3 = net.get("h1", "h2", "h3")
    h1.cmd(f"ping -i 1 -c {DURATION_S} {h2.IP()} > /dev/null &")
    h3.cmd(f"ping -i 2 -c {DURATION_S // 2} {h2.IP()} > /dev/null &")
    time.sleep(DURATION_S + 2)


def normal_mixed(net):
    """Web + ping + transferencias HTTP cortas. Tráfico corporativo típico."""
    h1, h2, h3, h4, h5 = net.get("h1", "h2", "h3", "h4", "h5")
    h4.cmd("mkdir -p /tmp/h4 && cd /tmp/h4 && "
           "dd if=/dev/urandom of=page.html bs=1K count=50 2>/dev/null && "
           "dd if=/dev/urandom of=img.jpg bs=1K count=200 2>/dev/null && "
           "python3 -m http.server 8000 > /dev/null 2>&1 &")
    h5.cmd("mkdir -p /tmp/h5 && cd /tmp/h5 && "
           "dd if=/dev/urandom of=doc.pdf bs=1K count=400 2>/dev/null && "
           "python3 -m http.server 8001 > /dev/null 2>&1 &")
    time.sleep(2)
    h1.cmd(f"ping -i 1 -c {DURATION_S} {h2.IP()} > /dev/null &")
    end = time.time() + DURATION_S
    while time.time() < end:
        h1.cmd(f"curl -s --limit-rate 200k http://{h4.IP()}:8000/page.html > /dev/null &")
        h2.cmd(f"curl -s --limit-rate 150k http://{h4.IP()}:8000/img.jpg > /dev/null &")
        h3.cmd(f"curl -s --limit-rate 300k http://{h5.IP()}:8001/doc.pdf > /dev/null &")
        time.sleep(4)


def normal_bulk_download(net):
    """ESCENARIO CRÍTICO: una sola IP descarga ~500 MB de otra a tasa alta.

    Es el caso de "alto volumen desde 1 IP" que debe quedar como Normal porque
    la conexión está establecida (1 flujo forward + 1 flujo return, sin SYNs
    nuevos). El modelo debe aprender a distinguir esto de un SYN flood.
    """
    h1, h2 = net.get("h1", "h2")
    h2.cmd("mkdir -p /tmp/h2 && cd /tmp/h2 && "
           "dd if=/dev/urandom of=big.bin bs=1M count=500 2>/dev/null && "
           "python3 -m http.server 8000 > /dev/null 2>&1 &")
    time.sleep(3)
    # Una sola descarga, sostenida durante toda la captura
    h1.cmd(f"curl -s http://{h2.IP()}:8000/big.bin > /dev/null &")
    time.sleep(DURATION_S)


# ============================================================
# DoS  — todos sin -k -s, src_port aleatorio (firma real)
# ============================================================

def dos_syn(net, pps, padding):
    """SYN flood TCP a puerto 80, src_port aleatorio."""
    h1, h2 = net.get("h1", "h2")
    interval_us = max(int(1_000_000 / pps), 1)
    cnt = int(pps * DURATION_S * 1.2)
    h1.cmd(f"hping3 -S -p 80 -d {padding} -i u{interval_us} -c {cnt} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_ack(net):
    """ACK flood: paquetes con flag ACK sin SYN previo. Engaña a firewalls."""
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 -A -p 80 -i u500 -c {DURATION_S * 2000} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_rst(net):
    """RST flood: paquetes RST que intentan terminar conexiones."""
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 -R -p 80 -i u500 -c {DURATION_S * 2000} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_icmp(net):
    """ICMP echo flood. Protocolo 1, paquetes ~42B."""
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 -1 -i u400 -c {DURATION_S * 2500} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_udp(net):
    """UDP flood a puerto fijo (53, simulando DNS amplification target)."""
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 -2 -p 53 -d 100 -i u500 -c {DURATION_S * 2000} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_mixed(net):
    """Multi-vector: SYN + ICMP simultáneos desde la misma IP."""
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 -S -p 80 -i u1000 -c {DURATION_S * 1000} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    h1.cmd(f"hping3 -1 -i u1000 -c {DURATION_S * 1000} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def dos_multi_target(net):
    """1 atacante (h1) atacando 3 víctimas (h2, h3, h4) en paralelo.

    Patrón (src bajo, dst alto, tasa alta) — para que el modelo NO confunda
    un DoS distribuido en el destino con tráfico de monitorización benigna.
    """
    h1 = net.get("h1")
    victims = [net.get(f"h{i}") for i in (2, 3, 4)]
    for v in victims:
        h1.cmd(f"hping3 -S -p 80 -i u1000 -c {DURATION_S * 1000} "
               f"{v.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


# ============================================================
# DDoS  — varias IPs origen
# ============================================================

def ddos_spoofed(net):
    """hping --rand-source: cada SYN lleva una IP origen falsa distinta.

    Tasa moderada (500 pps) porque cada SYN crea un flujo nuevo en OVS y
    no queremos saturar la tabla.
    """
    h1, h2 = net.get("h1", "h2")
    h1.cmd(f"hping3 --rand-source -S -p 80 -i u2000 -c {DURATION_S * 500} "
           f"{h2.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def ddos_real_hosts(net):
    """6 atacantes reales (h3..h8) contra h1, cada uno con protocolo distinto."""
    victim = net.get("h1")
    attackers = [net.get(f"h{i}") for i in range(3, 9)]
    # Mezcla de protocolos para enriquecer el patrón de DDoS
    protocols = [
        "-S -p 80",   # SYN
        "-S -p 443",  # SYN otro puerto
        "-A -p 80",   # ACK
        "-1",         # ICMP
        "-2 -p 53",   # UDP
        "-R -p 80",   # RST
    ]
    for a, proto in zip(attackers, protocols):
        a.cmd(f"hping3 {proto} -i u2000 -c {DURATION_S * 500} "
              f"{victim.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def ddos_low_rate_many(net):
    """6 atacantes a tasa MUY baja cada uno → total moderado.

    Caso difícil: ningún atacante individual destaca, pero agregado es DDoS.
    """
    victim = net.get("h1")
    attackers = [net.get(f"h{i}") for i in range(3, 9)]
    for a in attackers:
        # ~50 pps por atacante × 6 atacantes = ~300 pps total agregado
        a.cmd(f"hping3 -S -p 80 -i u20000 -c {DURATION_S * 50} "
              f"{victim.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


def ddos_multi_target(net):
    """4 atacantes (h3..h6) contra 2 víctimas (h1, h2) en paralelo.

    Patrón (src alto, dst alto, tasa alta) — cuadrante que sin este escenario
    se confundiría con pingall benigno (también alto en src y dst, pero baja tasa).
    """
    attackers = [net.get(f"h{i}") for i in range(3, 7)]
    victims = [net.get("h1"), net.get("h2")]
    for i, a in enumerate(attackers):
        v = victims[i % len(victims)]
        a.cmd(f"hping3 -S -p 80 -i u2000 -c {DURATION_S * 500} "
              f"{v.IP()} > /dev/null 2>&1 &")
    time.sleep(DURATION_S)


# ============================================================
# main
# ============================================================

SCENARIOS = [
    # --- NORMAL (3) ---
    ("normal", normal_idle,             "normal_idle"),
    ("normal", normal_mixed,            "normal_mixed"),
    ("normal", normal_bulk_download,    "normal_bulk_download"),
    # --- DoS (8) — TCP SYN/ACK/RST, ICMP, UDP, mixto, multi-objetivo ---
    ("dos",    lambda n: dos_syn(n, 1000,    0),  "dos_syn_1000pps_54B"),
    ("dos",    lambda n: dos_syn(n, 2000, 1460),  "dos_syn_2000pps_1514B"),
    ("dos",    dos_ack,                          "dos_ack_2000pps"),
    ("dos",    dos_rst,                          "dos_rst_2000pps"),
    ("dos",    dos_icmp,                         "dos_icmp_2500pps"),
    ("dos",    dos_udp,                          "dos_udp_2000pps"),
    ("dos",    dos_mixed,                        "dos_mixed_syn_icmp"),
    ("dos",    dos_multi_target,                 "dos_multi_target"),
    # --- DDoS (4) ---
    ("ddos",   ddos_spoofed,                     "ddos_spoofed"),
    ("ddos",   ddos_real_hosts,                  "ddos_real_hosts_mixed"),
    ("ddos",   ddos_low_rate_many,               "ddos_low_rate_distributed"),
    ("ddos",   ddos_multi_target,                "ddos_multi_target"),
]


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("ERROR: requiere sudo")

    for tool in ("hping3", "ryu-manager"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            sys.exit(f"ERROR: {tool} no instalado")

    setLogLevel("warning")
    mn_cleanup()

    if CSV_PATH.exists():
        bak = CSV_PATH.with_suffix(".csv.bak")
        print(f"Backup: {CSV_PATH.name} -> {bak.name}")
        CSV_PATH.replace(bak)

    total_min = len(SCENARIOS) * (DURATION_S + 15) / 60
    print(f"\nVamos a capturar {len(SCENARIOS)} escenarios "
          f"(~{total_min:.0f} minutos en total).\n")

    for label, fn, name in SCENARIOS:
        try:
            with_capture(label, fn, name)
        except Exception as e:
            print(f"[ERR] {name}: {e}")
            mn_cleanup()

    print(f"\n[OK] Captura completa: {CSV_PATH}")
    print("Vuelve a la conversación con Claude para inspeccionar y reentrenar.")


if __name__ == "__main__":
    main()
