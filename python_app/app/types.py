import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict


class AppType(str, Enum):
    UNKNOWN = "UNKNOWN"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "GOOGLE"
    FACEBOOK = "FACEBOOK"
    YOUTUBE = "YOUTUBE"
    TWITTER = "TWITTER"
    INSTAGRAM = "INSTAGRAM"
    NETFLIX = "NETFLIX"
    AMAZON = "AMAZON"
    MICROSOFT = "MICROSOFT"
    APPLE = "APPLE"
    WHATSAPP = "WHATSAPP"
    TELEGRAM = "TELEGRAM"
    TIKTOK = "TIKTOK"
    SPOTIFY = "SPOTIFY"
    ZOOM = "ZOOM"
    DISCORD = "DISCORD"
    GITHUB = "GITHUB"
    CLOUDFLARE = "CLOUDFLARE"


class PacketAction(str, Enum):
    FORWARD = "FORWARD"
    DROP = "DROP"
    INSPECT = "INSPECT"
    LOG_ONLY = "LOG_ONLY"


class ConnectionState(str, Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLASSIFIED = "CLASSIFIED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class FiveTuple:
    """
    Uniquely identifies a bidirectional network connection (flow).
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6 = TCP, 17 = UDP

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    def canonical(self) -> "FiveTuple":
        """Returns ordered representation for bidirectional lookup."""
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return self
        return self.reverse()

    def __str__(self) -> str:
        proto_str = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else f"P{self.protocol}")
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({proto_str})"


@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False

    def to_dict(self) -> dict:
        return {
            "flow": str(self.tuple),
            "src_ip": self.tuple.src_ip,
            "dst_ip": self.tuple.dst_ip,
            "src_port": self.tuple.src_port,
            "dst_port": self.tuple.dst_port,
            "protocol": "TCP" if self.tuple.protocol == 6 else ("UDP" if self.tuple.protocol == 17 else str(self.tuple.protocol)),
            "state": self.state.value,
            "app_type": self.app_type.value,
            "sni": self.sni,
            "packets": self.packets_in + self.packets_out,
            "bytes": self.bytes_in + self.bytes_out,
            "action": self.action.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen
        }


@dataclass
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0
    app_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "other_packets": self.other_packets,
            "active_connections": self.active_connections,
            "app_counts": self.app_counts
        }
