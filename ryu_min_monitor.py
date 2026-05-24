"""Ryu app mínima de monitorización + consulta al detector.
  ryu-manager ryu_min_monitor.py
Hace de switch L2, sondea flow stats cada 2s, calcula 7 features por flujo
y se las manda al detector (proceso aparte) por socket.
"""
import json, socket
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub

POLL = 2  # segundos

class MinMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev = {}  # (dpid, match_key) -> (pkts, bytes, t)
        self.monitor_thread = hub.spawn(self._monitor)

    # --- switch L2 básico (para que Mininet tenga conectividad) ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.logger.info("[switch] datapath conectado: %s", dp.id)

        p = dp.ofproto_parser
        match = p.OFPMatch()
        actions = [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                     dp.ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

    def _add_flow(self, dp, prio, match, actions):
        p = dp.ofproto_parser
        inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio,
                                 match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg; dp = msg.datapath
        p = dp.ofproto_parser; ofp = dp.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst, src = eth.dst, eth.src
        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][src] = in_port
        out_port = self.mac_to_port[dp.id].get(dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            # instala flujo por 5-TUPLA -> esto genera micro-flujos con --rand-source
            match = p.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(dp, 1, match, actions)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data))

    # --- monitor: sondea stats cada POLL segundos ---
    def _monitor(self):
        while True:
            self.logger.info("[monitor] sondeando %d switch(es)", len(self.datapaths))

            for dp in list(self.datapaths.values()):
                p = dp.ofproto_parser
                dp.send_msg(p.OFPFlowStatsRequest(dp))
            hub.sleep(POLL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        for st in ev.msg.body:
            if st.priority == 0:      # ignora el flujo por defecto
                continue
            key = str(st.match)
            dur = st.duration_sec + st.duration_nsec / 1e9
            pkts, byts = st.packet_count, st.byte_count
            ppkts, pbyts, _ = self.prev.get(key, (0, 0, 0))
            dpkts = max(pkts - ppkts, 0)
            dbyts = max(byts - pbyts, 0)
            self.prev[key] = (pkts, byts, dur)

            feats = {
                "src_port": st.match.get("tcp_src", 0) or st.match.get("udp_src", 0) or 0,
                "dst_port": st.match.get("tcp_dst", 0) or st.match.get("udp_dst", 0) or 0,
                "protocol": st.match.get("ip_proto", 0) or 0,
                "pkts_per_sec":  dpkts / POLL,
                "bytes_per_sec": dbyts / POLL,
                "avg_pkt_size":  (byts / pkts) if pkts else 0.0,
                "flow_age_sec":  dur,
            }

            verdict = self._ask_detector(feats)
            self.logger.info("[flujo] pkts/s=%.1f size=%.0f age=%.1f -> %s anomaly=%s conf=%.2f",
                             feats["pkts_per_sec"], feats["avg_pkt_size"],
                             feats["flow_age_sec"], verdict.get("attack_type"),
                             verdict.get("is_anomaly"), verdict.get("confidence", 0))

    def _ask_detector(self, feats):
        try:
            s = socket.create_connection(("127.0.0.1", 9999), timeout=1)
            s.sendall((json.dumps(feats) + "\n").encode())
            resp = s.makefile().readline()
            s.close()
            return json.loads(resp)
        except Exception as e:
            self.logger.error("[detector caído?] %s", e)
            return {}
