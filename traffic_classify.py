from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.revent import EventMixin
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
from pox.lib.packet.arp import arp
import time
import threading

log = core.getLogger()

FLOW_IDLE_TIMEOUT = 30
FLOW_HARD_TIMEOUT = 120
STATS_INTERVAL = 10
ICMP_FLOOD_THRESHOLD = 20


class TrafficClassifier(EventMixin):

    def __init__(self, block_udp=False, block_icmp=False):
        self.block_udp = block_udp
        self.block_icmp = block_icmp

        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.mac_table = {}
        self._icmp_interval_count = 0

        core.openflow.addListeners(self)

        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True
        )
        self._stats_thread.start()

        log.info("Controller STARTED")

    def _handle_ConnectionUp(self, event):
        self.mac_table[event.dpid] = {}
        log.info(f"Switch connected: {dpid_to_str(event.dpid)}")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.dpid
        in_port = event.port

        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}

        self.mac_table[dpid][packet.src] = in_port

        # L2 forwarding
        out_port = self.mac_table[dpid].get(packet.dst)
        if out_port is None:
            out_port = of.OFPP_FLOOD

        # ARP
        if packet.find(arp):
            self.stats["OTHER"] += 1
            self._forward_packet(event, of.OFPP_FLOOD)
            return

        ip_packet = packet.find(ipv4)

        if ip_packet:
            proto, label = self._classify(ip_packet)

            # FIREWALL
            if (self.block_udp and proto == ipv4.UDP_PROTOCOL) or \
               (self.block_icmp and proto == ipv4.ICMP_PROTOCOL):

                log.info(f"[BLOCK] Dropping {label}")

                msg = of.ofp_flow_mod()
                msg.priority = 20
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_proto = proto
                event.connection.send(msg)

                return

            # stats
            self.stats[label] += 1

            if label == "ICMP":
                self._icmp_interval_count += 1

            # install flow
            if out_port != of.OFPP_FLOOD:
                self._install_forward_flow(event, ip_packet, proto, out_port)

        else:
            self.stats["OTHER"] += 1

        self._forward_packet(event, out_port)

    def _classify(self, ip_pkt):
        proto = ip_pkt.protocol
        if proto == ipv4.ICMP_PROTOCOL:
            return proto, "ICMP"
        elif proto == ipv4.TCP_PROTOCOL:
            return proto, "TCP"
        elif proto == ipv4.UDP_PROTOCOL:
            return proto, "UDP"
        else:
            return proto, "OTHER"

    def _build_match(self, ip_pkt, proto):
        match = of.ofp_match()
        match.dl_type = ethernet.IP_TYPE
        match.nw_src = ip_pkt.srcip
        match.nw_dst = ip_pkt.dstip
        match.nw_proto = proto
        return match

    def _install_forward_flow(self, event, ip_pkt, proto, out_port):
        msg = of.ofp_flow_mod()
        msg.match = self._build_match(ip_pkt, proto)
        msg.priority = 10
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _forward_packet(self, event, out_port):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _stats_loop(self):
        while True:
            time.sleep(STATS_INTERVAL)
            self._print_stats()
            self._check_anomaly()
            self._icmp_interval_count = 0

    def _print_stats(self):
        total = sum(self.stats.values())

        if total == 0:
            log.info("[STATS] No traffic yet")
            return

        def pct(x):
            return (x / total) * 100

        log.info("=" * 50)
        log.info(f"[STATS] Total packets: {total}")

        log.info(
            f"[STATS] TCP: {self.stats['TCP']} ({pct(self.stats['TCP']):.1f}%) | "
            f"UDP: {self.stats['UDP']} ({pct(self.stats['UDP']):.1f}%) | "
            f"ICMP: {self.stats['ICMP']} ({pct(self.stats['ICMP']):.1f}%) | "
            f"OTHER: {self.stats['OTHER']} ({pct(self.stats['OTHER']):.1f}%)"
        )

        log.info("=" * 50)

    def _check_anomaly(self):
        if self._icmp_interval_count >= ICMP_FLOOD_THRESHOLD:
            log.warning("ICMP FLOOD DETECTED")


def launch(block_udp=False, block_icmp=False):
    if isinstance(block_udp, str):
        block_udp = block_udp.lower() in ("true", "1", "yes")
    if isinstance(block_icmp, str):
        block_icmp = block_icmp.lower() in ("true", "1", "yes")

    core.registerNew(TrafficClassifier,
                     block_udp=block_udp,
                     block_icmp=block_icmp)

    log.info(f"[INFO] Firewall settings → UDP: {block_udp}, ICMP: {block_icmp}")
