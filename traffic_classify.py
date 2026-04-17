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

# How long before an unused flow rule is removed from the switch
FLOW_IDLE_TIMEOUT = 30

# Maximum lifetime of any flow rule regardless of traffic
FLOW_HARD_TIMEOUT = 120

# How often the stats thread wakes up and prints (in seconds)
STATS_INTERVAL = 10

# If more than this many ICMP packets arrive in one interval, warn
ICMP_FLOOD_THRESHOLD = 20


class TrafficClassifier(EventMixin):

    def __init__(self, block_udp=False, block_icmp=False):

        # Firewall flags — set via command line on launch
        self.block_udp = block_udp
        self.block_icmp = block_icmp

        # Running count of packets seen per protocol
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

        # Stores size of each packet (in Mbits) per protocol
        # Used to calculate average speeds in _print_stats
        self.packet_sizes = {"TCP": [], "UDP": [], "ICMP": [], "OTHER": []}

        # MAC address to port mapping per switch: {dpid: {mac: port}}
        self.mac_table = {}

        # Tracks ICMP packets in the current interval only (resets each interval)
        self._icmp_interval_count = 0

        # Subscribe to OpenFlow events from any connected switch
        core.openflow.addListeners(self)

        # Stats thread runs in background, never blocks the main event loop
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True
        )
        self._stats_thread.start()

        log.info("Controller STARTED")

    def _handle_ConnectionUp(self, event):
        # New switch connected — set up its MAC table and install table-miss rule
        self.mac_table[event.dpid] = {}
        log.info(f"[INFO] Switch connected: {dpid_to_str(event.dpid)}")

        # Table-miss rule: if no other rule matches, send packet to controller
        # Priority 0 means this is always the last resort
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        # This fires every time a packet arrives with no matching flow rule

        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.dpid
        in_port = event.port

        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}

        # Learn which port this source MAC came from
        self.mac_table[dpid][packet.src] = in_port

        # Look up destination port — flood if we haven't seen this MAC yet
        out_port = self.mac_table[dpid].get(packet.dst)
        if out_port is None:
            out_port = of.OFPP_FLOOD

        # ARP must be flooded so hosts can resolve each other's MAC addresses
        # Without this, ping never works because h1 can't find h2's MAC
        if packet.find(arp):
            self.stats["OTHER"] += 1
            self._forward_packet(event, of.OFPP_FLOOD)
            return

        ip_packet = packet.find(ipv4)

        if ip_packet:
            proto, label = self._classify(ip_packet)

            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)

            # Firewall check — block before doing anything else
            if (self.block_udp and proto == ipv4.UDP_PROTOCOL) or \
               (self.block_icmp and proto == ipv4.ICMP_PROTOCOL):

                log.info(f"[BLOCK] {label} DROPPED {src_ip} → {dst_ip}")

                # Install a DROP rule: priority 20, no actions = switch drops in hardware
                # After this rule is installed, controller never sees this protocol again
                msg = of.ofp_flow_mod()
                msg.priority = 20
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_proto = proto
                event.connection.send(msg)

                return

            # Count this packet and record its size for speed calculation
            self.stats[label] += 1
            packet_size_mbits = len(event.ofp.data) * 8 / 1_000_000
            self.packet_sizes[label].append(packet_size_mbits)

            if label == "ICMP":
                self._icmp_interval_count += 1

            log.info(f"[INFO] {label} Packet: {src_ip} → {dst_ip}")

            # Only install a specific forwarding rule if we know the destination port
            # If we don't know yet, _forward_packet below will flood it
            if out_port != of.OFPP_FLOOD:
                self._install_forward_flow(event, ip_packet, proto, out_port)

        else:
            self.stats["OTHER"] += 1

        self._forward_packet(event, out_port)

    def _classify(self, ip_pkt):
        # Read the protocol number from the IP header and return a label
        # These numbers are defined in RFC 791: ICMP=1, TCP=6, UDP=17
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
        # Build an OpenFlow match that identifies this specific flow
        # Matching on src IP + dst IP + protocol ensures the rule is per-flow
        match = of.ofp_match()
        match.dl_type = ethernet.IP_TYPE   # 0x0800 — this is an IPv4 packet
        match.nw_src = ip_pkt.srcip
        match.nw_dst = ip_pkt.dstip
        match.nw_proto = proto
        return match

    def _install_forward_flow(self, event, ip_pkt, proto, out_port):
        # Install a rule that forwards matching packets out the correct port
        # Priority 10 — sits between table-miss (0) and firewall drop (20)
        msg = of.ofp_flow_mod()
        msg.match = self._build_match(ip_pkt, proto)
        msg.priority = 10
        msg.idle_timeout = FLOW_IDLE_TIMEOUT
        msg.hard_timeout = FLOW_HARD_TIMEOUT
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _forward_packet(self, event, out_port):
        # Send the specific packet that triggered PacketIn back into the network
        # This handles the current packet only — future packets use the flow rule
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    def _stats_loop(self):
        # Runs forever in a background thread
        # daemon=True means it dies automatically when the main program exits
        while True:
            time.sleep(STATS_INTERVAL)
            self._print_stats()
            self._check_anomaly()
            self._icmp_interval_count = 0   # reset for next interval

    def _print_stats(self):
        total = sum(self.stats.values())

        if total == 0:
            log.info("[STATS] No traffic yet")
            return

        def pct(x):
            return (x / total) * 100

        # Average speed = total bits seen for this protocol / interval length
        # Note: only first-packets reach the controller, so this reflects
        # controller-visible traffic, not total line-rate throughput
        def avg_speed(label):
            sizes = self.packet_sizes[label]
            if not sizes:
                return 0.0
            return sum(sizes) / STATS_INTERVAL

        log.info("=" * 60)
        log.info(f"[STATS] Total packets: {total}")
        log.info(
            f"[STATS] TCP:   {self.stats['TCP']:>4}  ({pct(self.stats['TCP']):5.1f}%)  "
            f"avg speed: {avg_speed('TCP'):.4f} Mbps"
        )
        log.info(
            f"[STATS] UDP:   {self.stats['UDP']:>4}  ({pct(self.stats['UDP']):5.1f}%)  "
            f"avg speed: {avg_speed('UDP'):.4f} Mbps"
        )
        log.info(
            f"[STATS] ICMP:  {self.stats['ICMP']:>4}  ({pct(self.stats['ICMP']):5.1f}%)  "
            f"avg speed: {avg_speed('ICMP'):.4f} Mbps"
        )
        log.info(
            f"[STATS] OTHER: {self.stats['OTHER']:>4}  ({pct(self.stats['OTHER']):5.1f}%)  "
            f"avg speed: {avg_speed('OTHER'):.4f} Mbps"
        )

        # Overall average across all protocols combined
        all_sizes = []
        for sizes in self.packet_sizes.values():
            all_sizes.extend(sizes)
        overall_avg = sum(all_sizes) / STATS_INTERVAL if all_sizes else 0.0

        log.info(f"[STATS] Overall avg speed (all protocols): {overall_avg:.4f} Mbps")
        log.info("=" * 60)

    def _check_anomaly(self):
        # If ICMP rate in the last interval crossed the threshold, something is off
        # Run "h1 ping -f h2" in Mininet to trigger this warning
        if self._icmp_interval_count >= ICMP_FLOOD_THRESHOLD:
            log.warning("ICMP FLOOD DETECTED")


def launch(block_udp=False, block_icmp=False):
    # Entry point called by POX when loading this component
    # Example: python pox.py log.level --DEBUG traffic_classify --block_udp

    # POX passes CLI flags as strings, so convert "True"/"False" to actual booleans
    if isinstance(block_udp, str):
        block_udp = block_udp.lower() in ("true", "1", "yes")
    if isinstance(block_icmp, str):
        block_icmp = block_icmp.lower() in ("true", "1", "yes")

    core.registerNew(TrafficClassifier,
                     block_udp=block_udp,
                     block_icmp=block_icmp)

    log.info(f"[INFO] Firewall settings → UDP: {block_udp}, ICMP: {block_icmp}")
