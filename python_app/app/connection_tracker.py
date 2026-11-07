from typing import Dict, List, Optional
from app.types import FiveTuple, Connection, ConnectionState, AppType, PacketAction


class ConnectionTracker:
    """
    Maintains flow states, packet/byte counters, TCP handshakes, and SNI domain mapping.
    """
    def __init__(self):
        self._connections: Dict[FiveTuple, Connection] = {}

    def get_or_create(self, five_tuple: FiveTuple, timestamp: float = 0.0) -> Connection:
        canonical_tuple = five_tuple.canonical()
        conn = self._connections.get(canonical_tuple)
        if not conn:
            conn = Connection(
                tuple=canonical_tuple,
                first_seen=timestamp,
                last_seen=timestamp
            )
            self._connections[canonical_tuple] = conn
        return conn

    def get(self, five_tuple: FiveTuple) -> Optional[Connection]:
        return self._connections.get(five_tuple.canonical())

    def update_packet(
        self,
        five_tuple: FiveTuple,
        length: int,
        timestamp: float,
        syn: bool = False,
        ack: bool = False,
        fin: bool = False
    ) -> Connection:
        conn = self.get_or_create(five_tuple, timestamp)
        conn.last_seen = timestamp

        # Direction tracking
        if five_tuple == conn.tuple:
            conn.packets_out += 1
            conn.bytes_out += length
        else:
            conn.packets_in += 1
            conn.bytes_in += length

        # TCP state progression
        if syn and not ack:
            conn.syn_seen = True
            conn.state = ConnectionState.NEW
        elif syn and ack:
            conn.syn_ack_seen = True
            conn.state = ConnectionState.ESTABLISHED
        elif fin:
            conn.fin_seen = True
            conn.state = ConnectionState.CLOSED

        return conn

    def list_connections(self) -> List[Connection]:
        return list(self._connections.values())

    def active_count(self) -> int:
        return len(self._connections)

    def clear(self) -> None:
        self._connections.clear()
