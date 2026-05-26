"""Ryu app de CAPTURA de dataset propio.

Sondea flow-stats cada POLL segundos, calcula las features (per-flow +
agregadas de ventana) con src/live_features.py, y escribe una fila por flujo
a un CSV, etiquetada con la clase que TÚ indiques al lanzar.

Uso (una clase por ejecución, el CSV se va acumulando en modo 'append'):

    CAPTURE_LABEL=normal CAPTURE_CSV=dataset.csv ryu-manager capture_app.py
    # ...generas tráfico normal (ping / iperf), Ctrl-C cuando tengas suficiente

    CAPTURE_LABEL=dos    CAPTURE_CSV=dataset.csv ryu-manager capture_app.py
    # ...flood desde UNA fuente

    CAPTURE_LABEL=ddos   CAPTURE_CSV=dataset.csv ryu-manager capture_app.py
    # ...flood con --rand-source (muchas fuentes)

IMPORTANTE: instala flujos por IP para que la diversidad de orígenes sea
visible. Con --rand-source eso crea un flujo por IP falsa, así que ACOTA el
ataque (--faster y -c, NUNCA --flood) o la tabla de flujos explota.
"""
import csv
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from src import live_features as lf

POLL = 2  # segundos entre sondeos (tu intervalo de diseño)
LABEL = os.environ.get("CAPTURE_LABEL", "unknown")
CSV_PATH = os.environ.get("CAPTURE_CSV", "dataset.csv")
# Si está activo, NO se escriben filas de flujos sin actividad en la ventana
# (packets_per_sec == 0 y bytes_per_sec == 0). Esto reduce drásticamente el
# ruido al capturar SYN floods con puerto origen aleatorio, donde la víctima
# crea miles de flujos RST con un único paquete que luego quedan inactivos.
FILTER_IDLE = os.environ.get("CAPTURE_FILTER_IDLE", "0") == "1"


class CaptureApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev = {}        # flow_key -> (pkts, bytes) del sondeo anterior
        self.prev_keys = set()  # claves de flujo vistas en el sondeo anterior
        self._init_csv()
        self.logger.info("[captura] etiqueta='%s'  csv='%s'", LABEL, CSV_PATH)
        self.monitor_thread = hub.spawn(self._monitor)

    def _init_csv(self):
        # Escribe la cabecera solo si el fichero aún no existe.
        if not os.path.exists(CSV_PATH):
            with open(CSV_PATH, "w", newline="") as f:
                csv.writer(f).writerow(lf.COLUMNS + ["label"])

    # ---------- switch L2 + instalación de flujos por IP ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        p = dp.ofproto_parser
        # regla por defecto: lo no reconocido va al controlador.
        # idle=0 -> la table-miss entry es PERMANENTE. Durante capturas largas
        # de un único flujo (típico en escenarios DoS o iperf), todo el tráfico
        # matchea la prio=1 y la catch-all se queda sin actividad. Si caducara
        # OVS dejaría de mandar packet_in y la captura se cortaría a mitad.
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)],
                       idle=0)

    def _add_flow(self, dp, prio, match, actions, idle=30):
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # idle_timeout: los flujos viejos expiran y la tabla no crece sin control.
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match,
                                 idle_timeout=idle, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        p = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]

        # Si es IP y conocemos la salida, instalamos un flujo POR IP (con puerto
        # L4 destino y protocolo). Así cada IP origen distinta = un flujo, y la
        # diversidad de orígenes se ve en las stats. NO casamos el puerto origen
        # (con --rand-source es aleatorio y multiplicaría los flujos sin aportar).
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip and out_port != ofp.OFPP_FLOOD:
            kwargs = dict(eth_type=ether_types.ETH_TYPE_IP,
                          ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=ip.proto)
            t = pkt.get_protocol(tcp.tcp)
            u = pkt.get_protocol(udp.udp)
            if t:
                kwargs["tcp_dst"] = t.dst_port
            elif u:
                kwargs["udp_dst"] = u.dst_port
            self._add_flow(dp, 1, p.OFPMatch(**kwargs), actions)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data))

    # ---------- sondeo periódico ----------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # Solo flujos instalados por nosotros (priority>0); ignora la regla por defecto.
        stats = [s for s in ev.msg.body if s.priority > 0]
        if not stats:
            return

        # Features agregadas de la ventana (una vez para todo el sondeo).
        win, keys_now = lf.window_features(stats, self.prev_keys, POLL)

        rows = []
        new_prev = {}
        for s in stats:
            pf = lf.per_flow_features(s, self.prev, POLL)
            new_prev[lf.flow_key(s)] = (s.packet_count, s.byte_count)
            # En modo captura limpia, descartamos flujos sin actividad reciente:
            # son los flujos RST residuales tras un SYN flood, todos casi
            # idénticos y sin información discriminativa.
            if FILTER_IDLE and pf["packets_per_sec"] == 0 and pf["bytes_per_sec"] == 0:
                continue
            row = {**pf, **win}
            rows.append([row[c] for c in lf.COLUMNS] + [LABEL])

        # Persistir el sondeo completo.
        with open(CSV_PATH, "a", newline="") as f:
            csv.writer(f).writerows(rows)

        self.prev = new_prev
        self.prev_keys = keys_now
        self.logger.info("[captura] +%d filas  label=%s  num_distinct_src_ips=%d  entropy=%.2f",
                         len(rows), LABEL, win["num_distinct_src_ips"], win["src_ip_entropy"])
