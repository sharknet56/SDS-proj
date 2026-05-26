"""Ryu app de DETECCIÓN + MITIGACIÓN en vivo, con métricas a InfluxDB para Grafana.

Calcula las 13 features (src/live_features.py, matching por IP), consulta al
detector por socket, mitiga según el tipo de ataque y escribe métricas en
InfluxDB (stack del Lab 4) para visualizarlas en Grafana.

    DoS  -> bloquear la IP origen (1 fuente real y única)
    DDoS -> bloquear la MAC origen de cada flujo atacante

Lo de bloquear por MAC en DDoS no es la opción más común (lo "típico" en una
red IP es rate-limit por destino), pero aquí es coherente con el modelo SDN:
el controlador lo ve TODO, incluida la capa 2, y eso permite cortar al
atacante directamente en lugar de penalizar el tráfico hacia la víctima.

Salvaguardas: persistencia (N sondeos seguidos), confianza mínima y timeout.

Métricas escritas en InfluxDB (db por defecto "SDS"):
  - detection   : una por sondeo. flujos, ataques, conteo por tipo, entropías,
                  num_distinct_src_ips... (series temporales).
  - attack_event: una por EPISODIO de ataque (al empezar). type, num_src, entropy.
                  Sirve para frecuencia/histórico de ataques.
  - blocks      : ciclo de vida de cada mitigación. active=1 al aplicar, active=0
                  al expirar; para DDoS, port/rate_kbps/ratelimited.

Lanzamiento (tres terminales):
  1. detector:  python serve_detector.py                  (venv 3.11)
  2. Ryu:       PYTHONPATH=. ryu-manager detect_app.py     (python del sistema)
  3. Mininet:   tráfico / ataques
(InfluxDB y Grafana arrancados como en el Lab 4.)
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

try:
    from influxdb import InfluxDBClient
    HAVE_INFLUX = True
except Exception:
    HAVE_INFLUX = False

POLL = 2
DETECTOR_ADDR = ("127.0.0.1", 9999)

# --- mitigación ---
MIT_PERSISTENCE = 3      # sondeos seguidos con ataque antes de actuar
MIT_MIN_CONF = 0.80      # confianza mínima del modelo para actuar
MIT_TIMEOUT = 30         # segundos que dura la regla (luego expira sola)
                         # 30 s = visible en Grafana sin esperar entre demos.
                         # En producción real: ~5 min con backoff por reincidencia.

# --- InfluxDB (Lab 4) ---
INFLUX_ENABLED = True
INFLUX_HOST = "127.0.0.1"
INFLUX_PORT = 8086
INFLUX_DB = "SDS"


class DetectApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}         # ip origen -> MAC origen (poblado en packet_in)
        self.datapaths = {}
        self.prev = {}
        self.prev_keys = set()
        self.attack_streak = 0      # sondeos consecutivos con ataque
        self.in_attack = False      # para detectar el inicio de un episodio
        self.mitigated = {}         # objetivo -> instante de expiración
        self.influx = self._influx_connect()
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("[detect] detector %s:%d | persist=%d conf>=%.2f timeout=%ds",
                         DETECTOR_ADDR[0], DETECTOR_ADDR[1],
                         MIT_PERSISTENCE, MIT_MIN_CONF, MIT_TIMEOUT)

    # ---------- InfluxDB ----------
    def _influx_connect(self):
        if not (INFLUX_ENABLED and HAVE_INFLUX):
            self.logger.info("[influx] desactivado o libreria ausente; sigo sin metricas")
            return None
        try:
            c = InfluxDBClient(host=INFLUX_HOST, port=INFLUX_PORT, database=INFLUX_DB)
            c.create_database(INFLUX_DB)
            self.logger.info("[influx] conectado a %s:%d db=%s", INFLUX_HOST, INFLUX_PORT, INFLUX_DB)
            return c
        except Exception as e:
            self.logger.error("[influx] no disponible (%s); sigo sin metricas", e)
            return None

    def _influx_write(self, measurement, fields, tags=None):
        if not self.influx:
            return
        try:
            self.influx.write_points([{"measurement": measurement,
                                       "tags": tags or {},
                                       "fields": fields}])
        except Exception as e:
            self.logger.error("[influx] write fallo: %s", e)

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
        if ip:
            # Recordamos la MAC asociada a esta IP origen. Lo usaremos al mitigar
            # un DDoS: el detector identifica los flujos atacantes por IP, pero
            # bloqueamos en L2 (la "gracia" de tener un controlador SDN: vemos
            # la MAC, así que cortamos al atacante directamente).
            self.ip_to_mac[ip.src] = eth.src
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
        self._prune_blocks()   # marca como expiradas (active=0) las mitigaciones vencidas

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
        predominant = max((t for t in verdicts if t not in ("Normal", "?")),
                          key=lambda t: verdicts[t], default="Normal")

        self.logger.info("[detect] %d flujos | %s | num_src=%d entropy=%.2f",
                         total, dict(verdicts),
                         win["num_distinct_src_ips"], win["src_ip_entropy"])

        # Métrica de detección (serie temporal).
        self._influx_write("detection", tags={"type": predominant}, fields={
            "total_flows": int(total), "attacks": int(attacks),
            "normal": int(verdicts.get("Normal", 0)),
            "dos": int(verdicts.get("DoS", 0)), "ddos": int(verdicts.get("DDoS", 0)),
            "num_distinct_src_ips": int(win["num_distinct_src_ips"]),
            "src_ip_entropy": float(win["src_ip_entropy"]),
            "dst_port_entropy": float(win["dst_port_entropy"]),
            "new_flows_per_sec": float(win["new_flows_per_sec"]),
            "attack_streak": int(self.attack_streak),
        })

        # Episodio de ataque: un evento al empezar (para frecuencia/histórico).
        if attacks > 0 and not self.in_attack:
            self.in_attack = True
            self._influx_write("attack_event", tags={"type": predominant}, fields={
                "count": 1, "num_src": int(win["num_distinct_src_ips"]),
                "entropy": float(win["src_ip_entropy"]),
            })
        elif attacks == 0:
            self.in_attack = False

        # Persistencia -> mitigación.
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
                # El flow_stat NO trae eth_src (instalamos los flujos casando
                # por IP, no por MAC). Resolvemos IP→MAC con el mapa que
                # poblamos en packet_in_handler.
                ip_src = lf.mget(m, "ipv4_src", None)
                if not ip_src:
                    continue
                mac_src = self.ip_to_mac.get(ip_src)
                if not mac_src:
                    self.logger.warning("[MITIGACION] DDoS desde %s pero MAC desconocida; "
                                        "salto este flujo", ip_src)
                    continue
                key = ("mac", mac_src)
                if self._recent(key, now):
                    continue
                self._block_mac(dp, mac_src)
                self.mitigated[key] = now + MIT_TIMEOUT

    def _recent(self, key, now):
        return key in self.mitigated and self.mitigated[key] > now

    def _prune_blocks(self):
        now = time.time()
        for key, exp in list(self.mitigated.items()):
            if exp <= now:
                # key[0] == "ip"  -> DoS, target = IP origen
                # key[0] == "mac" -> DDoS, target = MAC origen
                atype = "DoS" if key[0] == "ip" else "DDoS"
                self._influx_write("blocks",
                                   tags={"type": atype, "target": key[1]},
                                   fields={"active": 0, "expires": float(exp)})
                del self.mitigated[key]

    def _block_ip(self, dp, ip_src):
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                 hard_timeout=MIT_TIMEOUT, instructions=[]))
        self.logger.warning("[MITIGACION] DoS -> bloqueo IP origen %s durante %ds",
                            ip_src, MIT_TIMEOUT)
        self._influx_write("blocks", tags={"type": "DoS", "target": ip_src},
                           fields={"active": 1, "expires": time.time() + MIT_TIMEOUT})

    def _block_mac(self, dp, mac_src):
        p = dp.ofproto_parser
        # Match en L2: cualquier paquete con esa MAC origen. Instrucciones
        # vacías = drop. Prioridad 100 para ganar a las reglas IP de p=1.
        match = p.OFPMatch(eth_src=mac_src)
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=100, match=match,
                                 hard_timeout=MIT_TIMEOUT, instructions=[]))
        self.logger.warning("[MITIGACION] DDoS -> bloqueo MAC origen %s durante %ds",
                            mac_src, MIT_TIMEOUT)
        self._influx_write("blocks", tags={"type": "DDoS", "target": mac_src},
                           fields={"active": 1, "expires": time.time() + MIT_TIMEOUT})

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
