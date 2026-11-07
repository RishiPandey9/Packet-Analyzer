import fnmatch
from typing import Set, List, Dict, Any, Optional
from app.types import AppType, FiveTuple, PacketAction


class RuleManager:
    """
    Thread-safe Rule Manager for Deep Packet Inspection firewalling.
    Supports filtering based on:
      - Source / Destination IP
      - High-level Application (AppType)
      - Domain / SNI (exact or wildcard e.g. *.netflix.com)
      - Destination Port
    """
    def __init__(self, default_action: PacketAction = PacketAction.FORWARD):
        self.default_action = default_action
        self._blocked_ips: Set[str] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._blocked_ports: Set[int] = set()

    # --- IP Blocking ---
    def block_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip.strip())

    def unblock_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip.strip())

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        return sorted(list(self._blocked_ips))

    # --- App Blocking ---
    def block_app(self, app_type: AppType) -> None:
        self._blocked_apps.add(app_type)

    def unblock_app(self, app_type: AppType) -> None:
        self._blocked_apps.discard(app_type)

    def is_app_blocked(self, app_type: AppType) -> bool:
        return app_type in self._blocked_apps

    def get_blocked_apps(self) -> List[str]:
        return sorted([a.value for a in self._blocked_apps])

    # --- Domain Blocking ---
    def block_domain(self, domain: str) -> None:
        self._blocked_domains.add(domain.strip().lower())

    def unblock_domain(self, domain: str) -> None:
        self._blocked_domains.discard(domain.strip().lower())

    def is_domain_blocked(self, domain: str) -> bool:
        d = domain.strip().lower()
        for pattern in self._blocked_domains:
            if pattern == d:
                return True
            if pattern.startswith("*.") and d.endswith(pattern[1:]):
                return True
            if fnmatch.fnmatch(d, pattern):
                return True
        return False

    def get_blocked_domains(self) -> List[str]:
        return sorted(list(self._blocked_domains))

    # --- Port Blocking ---
    def block_port(self, port: int) -> None:
        self._blocked_ports.add(port)

    def unblock_port(self, port: int) -> None:
        self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        return port in self._blocked_ports

    def get_blocked_ports(self) -> List[int]:
        return sorted(list(self._blocked_ports))

    # --- Evaluation ---
    def evaluate(
        self,
        five_tuple: FiveTuple,
        app_type: AppType = AppType.UNKNOWN,
        domain: str = ""
    ) -> PacketAction:
        """
        Evaluates a packet or flow against active rules.
        Returns DROP if any rule matches, otherwise returns default action (FORWARD).
        """
        # 1. IP check
        if self.is_ip_blocked(five_tuple.src_ip) or self.is_ip_blocked(five_tuple.dst_ip):
            return PacketAction.DROP

        # 2. Port check
        if self.is_port_blocked(five_tuple.dst_port) or self.is_port_blocked(five_tuple.src_port):
            return PacketAction.DROP

        # 3. App check
        if app_type != AppType.UNKNOWN and self.is_app_blocked(app_type):
            return PacketAction.DROP

        # 4. Domain check
        if domain and self.is_domain_blocked(domain):
            return PacketAction.DROP

        return self.default_action

    def to_dict(self) -> dict:
        return {
            "blocked_ips": self.get_blocked_ips(),
            "blocked_apps": self.get_blocked_apps(),
            "blocked_domains": self.get_blocked_domains(),
            "blocked_ports": self.get_blocked_ports(),
            "default_action": self.default_action.value
        }

    def load_dict(self, data: dict) -> None:
        self._blocked_ips = set(data.get("blocked_ips", []))
        self._blocked_apps = {AppType(a) for a in data.get("blocked_apps", []) if a in AppType.__members__}
        self._blocked_domains = set(data.get("blocked_domains", []))
        self._blocked_ports = set(data.get("blocked_ports", []))
        if "default_action" in data:
            self.default_action = PacketAction(data["default_action"])
