import os
import time
from typing import Optional, Dict, Any, List

from app.types import FiveTuple, AppType, PacketAction, ConnectionState, DPIStats, Connection
from app.packet_parser import PacketParser, ParsedPacket
from app.sni_extractor import SNIExtractor
from app.connection_tracker import ConnectionTracker
from app.fast_path import FastPath
from app.rule_manager import RuleManager
from app.pcap_handler import PcapReader, PcapWriter


class DpiEngine:
    """
    Core Deep Packet Inspection Engine.
    Processes packets from PCAP, performs flow tracking, extracts SNI / HTTP Host,
    applies firewall rules, maintains fast-path cache, and outputs filtered traffic.
    """
    def __init__(self, rule_manager: Optional[RuleManager] = None):
        self.rule_manager = rule_manager or RuleManager()
        self.tracker = ConnectionTracker()
        self.fast_path = FastPath()
        self.stats = DPIStats()

    def reset(self) -> None:
        self.tracker.clear()
        self.fast_path.clear()
        self.stats = DPIStats()

    def process_packet(
        self,
        raw_data: bytes,
        ts_sec: int = 0,
        ts_usec: int = 0
    ) -> PacketAction:
        length = len(raw_data)
        self.stats.total_packets += 1
        self.stats.total_bytes += length
        timestamp = ts_sec + (ts_usec / 1_000_000.0)

        parsed: Optional[ParsedPacket] = PacketParser.parse(raw_data, ts_sec, ts_usec)
        if not parsed:
            self.stats.other_packets += 1
            # Forward non-IP / unparsed packets by default
            self.stats.forwarded_packets += 1
            return PacketAction.FORWARD

        if parsed.five_tuple.protocol == 6:
            self.stats.tcp_packets += 1
        elif parsed.five_tuple.protocol == 17:
            self.stats.udp_packets += 1
        else:
            self.stats.other_packets += 1

        # 1. Check if connection is already known and blocked
        conn = self.tracker.update_packet(
            parsed.five_tuple, length, timestamp,
            syn=parsed.syn, ack=parsed.ack, fin=parsed.fin
        )

        if conn.state == ConnectionState.BLOCKED:
            self.stats.dropped_packets += 1
            return PacketAction.DROP

        # 2. Deep Packet Inspection: inspect payload if not yet classified
        domain = conn.sni
        app_type = conn.app_type

        if conn.state != ConnectionState.CLASSIFIED and parsed.payload:
            extracted_domain = SNIExtractor.extract_domain(parsed.payload)
            if extracted_domain:
                domain = extracted_domain
                conn.sni = domain
                app_type = SNIExtractor.domain_to_app_type(domain)
                conn.app_type = app_type
                conn.state = ConnectionState.CLASSIFIED

                # Track App Count
                app_name = app_type.value
                self.stats.app_counts[app_name] = self.stats.app_counts.get(app_name, 0) + 1

        # Port-based fallback classification if connection closes without payload
        if conn.app_type == AppType.UNKNOWN:
            if parsed.five_tuple.dst_port == 80 or parsed.five_tuple.src_port == 80:
                conn.app_type = AppType.HTTP
            elif parsed.five_tuple.dst_port == 443 or parsed.five_tuple.src_port == 443:
                conn.app_type = AppType.HTTPS
            elif parsed.five_tuple.dst_port == 53 or parsed.five_tuple.src_port == 53:
                conn.app_type = AppType.DNS

        # 3. Rule Evaluation
        action = self.rule_manager.evaluate(
            parsed.five_tuple,
            app_type=conn.app_type,
            domain=conn.sni
        )
        conn.action = action

        if action == PacketAction.DROP:
            conn.state = ConnectionState.BLOCKED
            self.fast_path.update(parsed.five_tuple, PacketAction.DROP)
            self.stats.dropped_packets += 1
        else:
            if conn.state == ConnectionState.CLASSIFIED:
                self.fast_path.update(parsed.five_tuple, PacketAction.FORWARD)
            self.stats.forwarded_packets += 1

        return action

    def process_pcap(
        self,
        input_pcap_path: str,
        output_pcap_path: Optional[str] = None
    ) -> DPIStats:
        """
        Reads input PCAP, processes each packet, and optionally writes forwarded packets to output PCAP.
        """
        self.reset()
        start_time = time.time()

        writer = None
        if output_pcap_path:
            writer = PcapWriter(output_pcap_path)
            writer.__enter__()

        try:
            with PcapReader(input_pcap_path) as reader:
                for ts_sec, ts_usec, raw_data in reader.packets():
                    action = self.process_packet(raw_data, ts_sec, ts_usec)
                    if writer and action == PacketAction.FORWARD:
                        writer.write_packet(raw_data, ts_sec, ts_usec)
        finally:
            if writer:
                writer.__exit__(None, None, None)

        self.stats.active_connections = self.tracker.active_count()
        return self.stats

    def generate_report(self) -> str:
        """
        Generates a human-readable text report matching the C++ DPI engine output.
        """
        s = self.stats
        duration = 0.0
        lines = [
            "==================================================",
            "           DPI ENGINE INSPECTION REPORT           ",
            "==================================================",
            f"Total Packets Inspected : {s.total_packets:,}",
            f"Total Bytes             : {s.total_bytes:,}",
            f"Forwarded Packets       : {s.forwarded_packets:,}",
            f"Dropped Packets         : {s.dropped_packets:,}",
            f"TCP Packets             : {s.tcp_packets:,}",
            f"UDP Packets             : {s.udp_packets:,}",
            f"Other Packets           : {s.other_packets:,}",
            f"Active Connections      : {s.active_connections:,}",
            "--------------------------------------------------",
            "Applications Detected:"
        ]
        if s.app_counts:
            for app_name, count in sorted(s.app_counts.items(), key=lambda x: -x[1]):
                lines.append(f"  - {app_name:<16}: {count} packet(s)")
        else:
            lines.append("  (No specific SNI applications identified)")

        lines.append("--------------------------------------------------")
        lines.append(f"Blocked Rules: IPs={len(self.rule_manager.get_blocked_ips())}, "
                     f"Apps={len(self.rule_manager.get_blocked_apps())}, "
                     f"Domains={len(self.rule_manager.get_blocked_domains())}, "
                     f"Ports={len(self.rule_manager.get_blocked_ports())}")
        lines.append("==================================================")
        return "\n".join(lines)
