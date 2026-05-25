"""Ryu app de DETECCIÓN + MITIGACIÓN en vivo.

Calcula las 11 features (src/live_features.py, matching por IP), consulta al
detector por socket y, si confirma un ataque de forma sostenida, aplica una
mitigación según el tipo:

    DoS  -> bloquear la IP origen (fuente real y única)
    DDoS -> bloquear la MAC origen del atacante. Aunque el atacante use
            --rand-source para spoofear IPs, la MAC L2 sigue siendo la del
            host real, así que cortamos el tráfico en origen. Para mapear
            ip_src -> eth_src aprendemos en packet_in (ver self.ip_to_mac).

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
MIT_TIMEOUT = 1200         # segundos que dura la regla (luego expira sola)


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
        self.ip_to_mac = {}         # ip_src -> eth_src aprendido en packet_in
        self.mac_to_ips = {}        # eth_src -> set(ip_src) (para limpiar flujos al bloquear)
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
        # Table-miss permanente (idle=0). Si expira, nada llega al controlador
        # y el switch se queda sordo: ni se instalan flujos nuevos ni hay ping.
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)],
                       idle=0)

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
        if ip:
            # Aprende ip_src -> eth_src. Con --rand-source habrá muchas IPs
            # falsas apuntando todas a la misma MAC real del atacante; eso es
            # justo lo que queremos para bloquear por MAC ante un DDoS.
            self.ip_to_mac[ip.src] = eth.src
            self.mac_to_ips.setdefault(eth.src, set()).add(ip.src)
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
            self._mitigate(zip(stats, results))

    # ---------- mitigación ----------
    def _mitigate(self, pairs):
        # Las reglas se instalan en TODOS los switches conocidos, no solo en
        # el que ha disparado la detección. Con tree,depth=2,fanout=2 el
        # tráfico pasa por varios switches y bloquear en uno solo deja la
        # red corriendo en los demás.
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
                self._block_ip(ip_src)
                self.mitigated[key] = now + MIT_TIMEOUT
            elif atype == "DDoS":
                ip_src = lf.mget(m, "ipv4_src", None)
                if not ip_src:
                    continue
                mac_src = self.ip_to_mac.get(ip_src)
                if not mac_src:
                    # Sin mapeo aprendido no podemos bloquear por MAC; lo
                    # registramos para diagnosticar y saltamos este flujo.
                    self.logger.warning("[MITIGACION] DDoS: sin MAC para ip_src=%s", ip_src)
                    continue
                key = ("mac", mac_src)
                if self._recent(key, now):
                    continue
                self._block_mac(mac_src)
                self.mitigated[key] = now + MIT_TIMEOUT

    def _recent(self, key, now):
        return key in self.mitigated and self.mitigated[key] > now

    def _block_ip(self, ip_src):
        n = 0
        for dp in self.datapaths.values():
            p = dp.ofproto_parser
            match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
            # instrucciones vacías = drop
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                     hard_timeout=MIT_TIMEOUT, instructions=[]))
            n += 1
        self.logger.warning("[MITIGACION] DoS -> drop ipv4_src=%s en %d switch(es) durante %ds",
                            ip_src, n, MIT_TIMEOUT)

    def _block_mac(self, mac_src):
        # 1) Instala el drop priority=100 con match(eth_src) en todos los
        #    switches: resistente a IP spoofing, corta el tráfico en origen.
        # 2) Limpia los priority=1 que esa MAC dejó instalados con IPs
        #    falsas. Si no, durante 30s ocupan tabla y bloquean otros
        #    pings (la tabla de OVS llega a saturarse rápido).
        n_blocks = 0
        n_cleaned = 0
        spoofed_ips = list(self.mac_to_ips.get(mac_src, ()))
        for dp in self.datapaths.values():
            p = dp.ofproto_parser
            ofp = dp.ofproto
            match = p.OFPMatch(eth_src=mac_src)
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                     hard_timeout=MIT_TIMEOUT, instructions=[]))
            n_blocks += 1
            for ip in spoofed_ips:
                del_match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
                dp.send_msg(p.OFPFlowMod(datapath=dp,
                                         command=ofp.OFPFC_DELETE,
                                         out_port=ofp.OFPP_ANY,
                                         out_group=ofp.OFPG_ANY,
                                         match=del_match))
                n_cleaned += 1
        self.logger.warning("[MITIGACION] DDoS -> drop eth_src=%s en %d switch(es) | "
                            "borrados %d flujos priority=1 (%d IPs falsas) durante %ds",
                            mac_src, n_blocks, n_cleaned, len(spoofed_ips), MIT_TIMEOUT)

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
