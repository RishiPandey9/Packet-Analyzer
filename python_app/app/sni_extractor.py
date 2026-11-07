import struct
from typing import Optional
from app.types import AppType


class SNIExtractor:
    """
    Deep Packet Inspection: Extracts Server Name Indication (SNI) from TLS Client Hello,
    and Host header from HTTP requests. Also maps domains to high-level application types.
    """
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @classmethod
    def is_tls_client_hello(cls, payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        # Byte 0: Content Type Handshake (0x16)
        if payload[0] != cls.CONTENT_TYPE_HANDSHAKE:
            return False
        # Bytes 1-2: TLS Version (0x0300 to 0x0304)
        version = struct.unpack('>H', payload[1:3])[0]
        if version < 0x0300 or version > 0x0304:
            return False
        # Byte 5: Handshake Type Client Hello (0x01)
        if payload[5] != cls.HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @classmethod
    def extract_tls_sni(cls, payload: bytes) -> Optional[str]:
        """
        Parses TLS Client Hello handshake and returns SNI domain if present.
        """
        if not cls.is_tls_client_hello(payload):
            return None

        try:
            length = len(payload)
            offset = 5  # Skip TLS record header

            # Handshake header (4 bytes: type 1B, length 3B)
            offset += 4

            # Client Version (2 bytes) + Random (32 bytes)
            offset += 34
            if offset >= length:
                return None

            # Session ID (1 byte length + data)
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > length:
                return None

            # Cipher Suites (2 bytes length + data)
            cipher_suites_len = struct.unpack('>H', payload[offset:offset + 2])[0]
            offset += 2 + cipher_suites_len
            if offset >= length:
                return None

            # Compression Methods (1 byte length + data)
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            if offset + 2 > length:
                return None

            # Extensions Length
            extensions_len = struct.unpack('>H', payload[offset:offset + 2])[0]
            offset += 2
            extensions_end = min(offset + extensions_len, length)

            # Parse Extensions
            while offset + 4 <= extensions_end:
                ext_type, ext_len = struct.unpack('>HH', payload[offset:offset + 4])
                offset += 4

                if offset + ext_len > extensions_end:
                    break

                if ext_type == cls.EXTENSION_SNI:
                    # SNI extension structure:
                    # 2 bytes: SNI List Length
                    # 1 byte:  SNI Type (0 = Host Name)
                    # 2 bytes: SNI Name Length
                    # N bytes: Hostname
                    if ext_len < 5:
                        break
                    sni_list_len = struct.unpack('>H', payload[offset:offset + 2])[0]
                    if sni_list_len < 3:
                        break
                    sni_type = payload[offset + 2]
                    sni_len = struct.unpack('>H', payload[offset + 3:offset + 5])[0]

                    if sni_type == cls.SNI_TYPE_HOSTNAME and sni_len <= ext_len - 5:
                        hostname_bytes = payload[offset + 5:offset + 5 + sni_len]
                        return hostname_bytes.decode('utf-8', errors='ignore').strip()

                offset += ext_len

        except Exception:
            return None

        return None

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
        return any(payload.startswith(m) for m in methods)

    @classmethod
    def extract_http_host(cls, payload: bytes) -> Optional[str]:
        """
        Extracts Host header from plain HTTP request payload.
        """
        if not cls.is_http_request(payload):
            return None
        try:
            text = payload[:1024].decode('latin1', errors='ignore')
            lines = text.split('\r\n')
            for line in lines[1:]:
                if not line:
                    break
                if line.lower().startswith('host:'):
                    return line[5:].strip().split(':')[0]
        except Exception:
            pass
        return None

    @classmethod
    def extract_dns_query(cls, payload: bytes) -> Optional[str]:
        """
        Parses standard DNS query on UDP port 53 and extracts the queried domain name.
        """
        if len(payload) < 12:
            return None
        try:
            # Flags: byte 2 (QR bit: 0 for query, 1 for response)
            qr = (payload[2] >> 7) & 1
            questions = struct.unpack('>H', payload[4:6])[0]
            if questions == 0:
                return None

            offset = 12
            labels = []
            while offset < len(payload):
                length = payload[offset]
                offset += 1
                if length == 0:
                    break
                if length > 63 or offset + length > len(payload):
                    return None
                labels.append(payload[offset:offset + length].decode('ascii', errors='ignore'))
                offset += length

            if labels:
                return '.'.join(labels)
        except Exception:
            pass
        return None

    @classmethod
    def extract_domain(cls, payload: bytes) -> Optional[str]:
        """
        Tries TLS SNI extraction, HTTP Host header extraction, and DNS query domain extraction.
        """
        domain = cls.extract_tls_sni(payload)
        if domain:
            return domain
        domain = cls.extract_http_host(payload)
        if domain:
            return domain
        return cls.extract_dns_query(payload)

    @staticmethod
    def domain_to_app_type(domain: str) -> AppType:
        """
        Maps extracted domain name to an AppType classification.
        """
        d = domain.lower()
        if "youtube.com" in d or "googlevideo.com" in d or "youtu.be" in d:
            return AppType.YOUTUBE
        if "facebook.com" in d or "fbcdn.net" in d or "fbsbx.com" in d:
            return AppType.FACEBOOK
        if "instagram.com" in d or "cdninstagram.com" in d:
            return AppType.INSTAGRAM
        if "netflix.com" in d or "nflxvideo.net" in d or "nflximg.net" in d:
            return AppType.NETFLIX
        if "twitter.com" in d or "twimg.com" in d or "x.com" in d:
            return AppType.TWITTER
        if "google.com" in d or "googleapis.com" in d or "gstatic.com" in d:
            return AppType.GOOGLE
        if "whatsapp.com" in d or "whatsapp.net" in d:
            return AppType.WHATSAPP
        if "telegram.org" in d or "t.me" in d:
            return AppType.TELEGRAM
        if "tiktok.com" in d or "tiktokcdn.com" in d or "byteoversea.com" in d:
            return AppType.TIKTOK
        if "spotify.com" in d or "scdn.co" in d:
            return AppType.SPOTIFY
        if "zoom.us" in d:
            return AppType.ZOOM
        if "discord.com" in d or "discord.gg" in d or "discordapp.com" in d:
            return AppType.DISCORD
        if "github.com" in d or "githubusercontent.com" in d:
            return AppType.GITHUB
        if "cloudflare.com" in d or "cloudflare.net" in d:
            return AppType.CLOUDFLARE
        if "amazon.com" in d or "amazonaws.com" in d:
            return AppType.AMAZON
        if "microsoft.com" in d or "azure.com" in d or "live.com" in d:
            return AppType.MICROSOFT
        if "apple.com" in d or "icloud.com" in d:
            return AppType.APPLE

        return AppType.HTTPS
