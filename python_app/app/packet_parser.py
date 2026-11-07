import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from app.types import FiveTuple


@dataclass
class ParsedPacket:
    five_tuple: FiveTuple
    ts_sec: int
    ts_usec: int
    raw_data: bytes
    eth_offset: int
    ip_offset: int
    transport_offset: int
    payload_offset: int
    payload: bytes
    src_mac: str = ""
    dst_mac: str = ""
    tcp_flags: int = 0
    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False


class PacketParser:
    """
    Decodes Ethernet, IPv4, TCP, and UDP layers from raw packet bytes.
    """
    @staticmethod
    def parse(raw_data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> Optional[ParsedPacket]:
        length = len(raw_data)
        if length < 14:  # Minimum Ethernet frame
            return None

        # 1. Ethernet Header (14 bytes)
        eth_offset = 0
        dst_mac = ':'.join(f'{b:02x}' for b in raw_data[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in raw_data[6:12])
        eth_type = struct.unpack('>H', raw_data[12:14])[0]
        ip_offset = 14

        # Handle 802.1Q VLAN Tagging (4 extra bytes)
        if eth_type == 0x8100:
            if length < 18:
                return None
            eth_type = struct.unpack('>H', raw_data[16:18])[0]
            ip_offset = 18

        # We currently inspect IPv4 (EtherType 0x0800)
        if eth_type != 0x0800:
            return None

        # 2. IPv4 Header (at least 20 bytes)
        if length < ip_offset + 20:
            return None

        ver_ihl = raw_data[ip_offset]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4

        if version != 4 or ihl < 20 or length < ip_offset + ihl:
            return None

        protocol = raw_data[ip_offset + 9]
        src_ip = socket.inet_ntoa(raw_data[ip_offset + 12:ip_offset + 16])
        dst_ip = socket.inet_ntoa(raw_data[ip_offset + 16:ip_offset + 20])

        transport_offset = ip_offset + ihl
        payload_offset = transport_offset
        payload = b''
        tcp_flags = 0
        syn = False
        ack = False
        fin = False
        rst = False

        src_port = 0
        dst_port = 0

        # 3. Transport Layer
        if protocol == 6:  # TCP
            if length < transport_offset + 20:
                return None
            src_port, dst_port, seq, ack_num, offset_flags = struct.unpack(
                '>HHIIH', raw_data[transport_offset:transport_offset + 14]
            )
            data_offset = (offset_flags >> 12) * 4
            tcp_flags = offset_flags & 0x01FF

            syn = bool(tcp_flags & 0x0002)
            rst = bool(tcp_flags & 0x0004)
            fin = bool(tcp_flags & 0x0001)
            ack = bool(tcp_flags & 0x0010)

            payload_offset = transport_offset + data_offset
            if length >= payload_offset:
                payload = raw_data[payload_offset:]

        elif protocol == 17:  # UDP
            if length < transport_offset + 8:
                return None
            src_port, dst_port, udp_len, udp_checksum = struct.unpack(
                '>HHHH', raw_data[transport_offset:transport_offset + 8]
            )
            payload_offset = transport_offset + 8
            if length >= payload_offset:
                payload = raw_data[payload_offset:]

        else:
            return None

        five_tuple = FiveTuple(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )

        return ParsedPacket(
            five_tuple=five_tuple,
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            raw_data=raw_data,
            eth_offset=eth_offset,
            ip_offset=ip_offset,
            transport_offset=transport_offset,
            payload_offset=payload_offset,
            payload=payload,
            src_mac=src_mac,
            dst_mac=dst_mac,
            tcp_flags=tcp_flags,
            syn=syn,
            ack=ack,
            fin=fin,
            rst=rst
        )
