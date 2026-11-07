import struct
from typing import Generator, Tuple, Optional


class PcapReader:
    """
    Reads standard PCAP packet capture files.
    """
    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self.magic = 0
        self.version_major = 0
        self.version_minor = 0
        self.snaplen = 0
        self.linktype = 0
        self.byte_order = '<'  # '<' for little endian, '>' for big endian

    def __enter__(self):
        self._file = open(self.filepath, 'rb')
        self._read_global_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()

    def _read_global_header(self):
        # 24-byte PCAP global header
        raw_header = self._file.read(24)
        if len(raw_header) < 24:
            raise ValueError("Invalid PCAP: file too short for global header")

        magic = struct.unpack('<I', raw_header[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            self.byte_order = '<'
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            self.byte_order = '>'
        else:
            raise ValueError(f"Unrecognized PCAP magic number: 0x{magic:08x}")

        (
            self.magic,
            self.version_major,
            self.version_minor,
            thiszone,
            sigfigs,
            self.snaplen,
            self.linktype
        ) = struct.unpack(f'{self.byte_order}IHHIIII', raw_header)

    def packets(self) -> Generator[Tuple[int, int, bytes], None, None]:
        """
        Yields (ts_sec, ts_usec, packet_bytes)
        """
        opened_here = False
        if self._file is None:
            self._file = open(self.filepath, 'rb')
            self._read_global_header()
            opened_here = True
        try:
            while True:
                pkt_hdr = self._file.read(16)
                if not pkt_hdr or len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, caplen, origlen = struct.unpack(f'{self.byte_order}IIII', pkt_hdr)
                data = self._file.read(caplen)
                if len(data) < caplen:
                    break
                yield ts_sec, ts_usec, data
        finally:
            if opened_here and self._file:
                self._file.close()
                self._file = None


class PcapWriter:
    """
    Writes standard PCAP files (e.g. filtered traffic).
    """
    def __init__(self, filepath: str, linktype: int = 1, snaplen: int = 65535):
        self.filepath = filepath
        self.linktype = linktype
        self.snaplen = snaplen
        self._file = None

    def __enter__(self):
        self._file = open(self.filepath, 'wb')
        # Write global header
        hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, self.snaplen, self.linktype)
        self._file.write(hdr)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()

    def write_packet(self, data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> None:
        pkt_len = len(data)
        pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, pkt_len, pkt_len)
        self._file.write(pkt_hdr)
        self._file.write(data)
