"""Ryu app de DETECCIÓN + MITIGACIÓN en vivo.

Calcula las 11 features (src/live_features.py, matching por IP), consulta al
detector por socket y, si confirma un ataque de forma sostenida, aplica una
mitigación según el tipo:

    DoS  -> bloquear la IP origen (fuente real y única)
    DDoS -> rate-limit del tráfico hacia la víctima:puerto (origen no fiable;
            se protege el servicio atacado sin tocar el resto del host)

Salvaguardas contra falsos positivos:
  - PERSISTENCIA: solo actúa tras varios sondeos seguidos con ataque.
  - CONFIANZA:    solo actúa si la confianza del modelo es alta.
  - TIMEOUT:      las reglas de mitigación expiran solas (un error no es eterno).

Lanzamiento (tres terminales, como siempre):
  1. detector:  python serve_detector.py        (venv 3.11)
  2. Ryu:       PYTHONPATH=. ryu-manager detect_app.py   (python del sistema)
  3. Mininet:   tráfico / ataques
"""
import json
import socket
import time
from collections import Counter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from src import live_features as lf

POLL = 2
DETECTOR_ADDR = ("127.0.0.1", 9999)

# --- parámetros de mitigación ---
MIT_PERSISTENCE = 3      # sondeos seguidos con ataque antes de actuar
MIT_MIN_CONF = 0.80      # confianza mínima del modelo para actuar
MIT_TIMEOUT = 30         # segundos que dura la regla (luego expira sola)
DDOS_RATE_KBPS = 1000    # tasa a la que se limita la víctima:puerto en un DDoS
# Si los meters de tu OVS fallan (soporte quisquilloso), pon False: en vez de
# limitar, bloqueará temporalmente la víctima:puerto (más brusco pero fiable).
USE_METER = True


class DetectApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev = {}
        self.prev_keys = set()
        self.attack_streak = 0      # sondeos consecutivos con ataque
        self.mitigated = {}         # objetivo -> instante de expiración
        self.next_meter_id = 1
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("[detect] detector en %s:%d | mitigacion: persist=%d conf>=%.2f timeout=%ds",
                         DETECTOR_ADDR[0], DETECTOR_ADDR[1],
                         MIT_PERSISTENCE, MIT_MIN_CONF, MIT_TIMEOUT)

    # ---------- switch L2 + flujos por IP ----------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        p = dp.ofproto_parser
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)])

    def _add_flow(self, dp, prio, match, actions, idle=30):
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
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

    # ---------- sondeo + detección ----------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # priority == 1: solo los flujos de tráfico (no las reglas de mitigación, prio 100).
        stats = [s for s in ev.msg.body if s.priority == 1]
        if not stats:
            return

        win, keys_now = lf.window_features(stats, self.prev_keys, POLL)
        feats_list, new_prev = [], {}
        for s in stats:
            pf = lf.per_flow_features(s, self.prev, POLL)
            new_prev[lf.flow_key(s)] = (s.packet_count, s.byte_count)
            feats_list.append({**pf, **win})
        self.prev = new_prev
        self.prev_keys = keys_now

        results = self._ask_detector(feats_list)
        verdicts = Counter(v.get("attack_type", "?") for v in results)
        total = sum(verdicts.values())
        attacks = total - verdicts.get("Normal", 0)

        self.logger.info("[detect] %d flujos | %s | num_src=%d entropy=%.2f",
                         total, dict(verdicts),
                         win["num_distinct_src_ips"], win["src_ip_entropy"])

        # Persistencia: cuenta sondeos seguidos con ataque.
        self.attack_streak = self.attack_streak + 1 if attacks > 0 else 0
        if attacks > 0:
            self.logger.warning("[ALERTA] %d/%d flujos de ataque (racha=%d)",
                                 attacks, total, self.attack_streak)
        if self.attack_streak >= MIT_PERSISTENCE:
            self._mitigate(ev.msg.datapath, zip(stats, results))

    # ---------- mitigación ----------
    def _mitigate(self, dp, pairs):
        now = time.time()
        for stat, v in pairs:
            if not v.get("is_anomaly") or v.get("confidence", 0) < MIT_MIN_CONF:
                continue
            m = stat.match
            atype = v.get("attack_type")
            if atype == "DoS":
                ip_src = lf.mget(m, "ipv4_src", None)
                if not ip_src:
                    continue
                key = ("ip", ip_src)
                if self._recent(key, now):
                    continue
                self._block_ip(dp, ip_src)
                self.mitigated[key] = now + MIT_TIMEOUT
            elif atype == "DDoS":
                ip_dst = lf.mget(m, "ipv4_dst", None)
                if not ip_dst:
                    continue
                proto = lf.mget(m, "ip_proto", 0)
                l4 = lf.mget(m, "tcp_dst", 0) or lf.mget(m, "udp_dst", 0) or 0
                key = ("vp", ip_dst, l4)
                if self._recent(key, now):
                    continue
                self._rate_limit(dp, ip_dst, l4, proto)
                self.mitigated[key] = now + MIT_TIMEOUT

    def _recent(self, key, now):
        return key in self.mitigated and self.mitigated[key] > now

    def _block_ip(self, dp, ip_src):
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        # instrucciones vacías = drop
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                 hard_timeout=MIT_TIMEOUT, instructions=[]))
        self.logger.warning("[MITIGACION] DoS -> bloqueo IP origen %s durante %ds",
                            ip_src, MIT_TIMEOUT)

    def _rate_limit(self, dp, ip_dst, l4_dst, ip_proto):
        p = dp.ofproto_parser
        ofp = dp.ofproto
        kwargs = dict(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_dst, ip_proto=ip_proto)
        if ip_proto == 6 and l4_dst:
            kwargs["tcp_dst"] = l4_dst
        elif ip_proto == 17 and l4_dst:
            kwargs["udp_dst"] = l4_dst
        match = p.OFPMatch(**kwargs)

        if USE_METER:
            try:
                mid = self.next_meter_id
                self.next_meter_id += 1
                band = p.OFPMeterBandDrop(rate=DDOS_RATE_KBPS, burst_size=DDOS_RATE_KBPS)
                dp.send_msg(p.OFPMeterMod(dp, command=ofp.OFPMC_ADD,
                                          flags=ofp.OFPMF_KBPS, meter_id=mid, bands=[band]))
                inst = [p.OFPInstructionMeter(mid),
                        p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                [p.OFPActionOutput(ofp.OFPP_NORMAL)])]
                dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                         hard_timeout=MIT_TIMEOUT, instructions=inst))
                self.logger.warning("[MITIGACION] DDoS -> rate-limit %s:%s a %d kbps durante %ds",
                                    ip_dst, l4_dst, DDOS_RATE_KBPS, MIT_TIMEOUT)
                return
            except Exception as e:
                self.logger.error("[MITIGACION] meter no disponible (%s); bloqueo temporal", e)

        # Fallback: bloquear la víctima:puerto (instrucciones vacías = drop).
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                 hard_timeout=MIT_TIMEOUT, instructions=[]))
        self.logger.warning("[MITIGACION] DDoS -> bloqueo %s:%s durante %ds (sin meter)",
                            ip_dst, l4_dst, MIT_TIMEOUT)

    def _ask_detector(self, feats_list):
        results = []
        try:
            s = socket.create_connection(DETECTOR_ADDR, timeout=3)
            rf = s.makefile("r")
            for feats in feats_list:
                s.sendall((json.dumps(feats) + "\n").encode())
                line = rf.readline()
                results.append(json.loads(line) if line else {})
            rf.close()
            s.close()
        except Exception as e:
            self.logger.error("[detector caido?] %s", e)
            results = [{} for _ in feats_list]
        return results
