from typing import Dict, Optional
from app.types import FiveTuple, PacketAction


class FastPath:
    """
    Fast Path Cache:
    Bypasses deep inspection for packets belonging to already classified/actioned connections.
    """
    def __init__(self):
        self._cache: Dict[FiveTuple, PacketAction] = {}

    def lookup(self, five_tuple: FiveTuple) -> Optional[PacketAction]:
        return self._cache.get(five_tuple.canonical())

    def update(self, five_tuple: FiveTuple, action: PacketAction) -> None:
        self._cache[five_tuple.canonical()] = action

    def clear(self) -> None:
        self._cache.clear()
