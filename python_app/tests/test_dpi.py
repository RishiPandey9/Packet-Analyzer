import os
import tempfile
import pytest
from app.types import FiveTuple, AppType, PacketAction, ConnectionState
from app.pcap_handler import PcapReader, PcapWriter
from app.packet_parser import PacketParser
from app.sni_extractor import SNIExtractor
from app.rule_manager import RuleManager
from app.connection_tracker import ConnectionTracker
from app.fast_path import FastPath
from app.dpi_engine import DpiEngine


def test_five_tuple_canonical():
    t1 = FiveTuple(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=54321, dst_port=443, protocol=6)
    t2 = FiveTuple(src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=443, dst_port=54321, protocol=6)
    assert t1.canonical() == t2.canonical()


def test_rule_manager_evaluations():
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)
    rules.block_domain("*.facebook.com")
    rules.block_ip("192.168.1.50")
    rules.block_port(8080)

    # Allowed
    t_normal = FiveTuple(src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443, protocol=6)
    assert rules.evaluate(t_normal, app_type=AppType.GOOGLE, domain="google.com") == PacketAction.FORWARD

    # Blocked by App
    assert rules.evaluate(t_normal, app_type=AppType.YOUTUBE, domain="youtube.com") == PacketAction.DROP

    # Blocked by Domain wildcard
    assert rules.evaluate(t_normal, app_type=AppType.UNKNOWN, domain="static.facebook.com") == PacketAction.DROP

    # Blocked by IP
    t_bad_ip = FiveTuple(src_ip="192.168.1.50", dst_ip="1.1.1.1", src_port=1234, dst_port=443, protocol=6)
    assert rules.evaluate(t_bad_ip) == PacketAction.DROP

    # Blocked by Port
    t_bad_port = FiveTuple(src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=8080, protocol=6)
    assert rules.evaluate(t_bad_port) == PacketAction.DROP


def test_sni_domain_classification():
    assert SNIExtractor.domain_to_app_type("www.youtube.com") == AppType.YOUTUBE
    assert SNIExtractor.domain_to_app_type("video.netflix.com") == AppType.NETFLIX
    assert SNIExtractor.domain_to_app_type("graph.facebook.com") == AppType.FACEBOOK
    assert SNIExtractor.domain_to_app_type("api.github.com") == AppType.GITHUB
    assert SNIExtractor.domain_to_app_type("unknown-service.com") == AppType.HTTPS


def test_pcap_read_write_roundtrip():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp_path = tmp.name

    try:
        # Write dummy packet
        dummy_data = b"\x00" * 60
        with PcapWriter(tmp_path) as writer:
            writer.write_packet(dummy_data, ts_sec=1700000000, ts_usec=123456)

        # Read back
        with PcapReader(tmp_path) as reader:
            pkts = list(reader.packets())
            assert len(pkts) == 1
            ts_sec, ts_usec, data = pkts[0]
            assert ts_sec == 1700000000
            assert ts_usec == 123456
            assert data == dummy_data
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_dpi_engine_on_real_pcap():
    test_pcap_path = os.path.join(os.path.dirname(__file__), "..", "..", "test_dpi.pcap")
    if not os.path.exists(test_pcap_path):
        pytest.skip("test_dpi.pcap not found")

    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)
    rules.block_ip("192.168.1.50")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as out_tmp:
        out_pcap_path = out_tmp.name

    try:
        engine = DpiEngine(rules)
        stats = engine.process_pcap(test_pcap_path, output_pcap_path=out_pcap_path)

        assert stats.total_packets == 77
        assert stats.dropped_packets >= 6  # 5 from blocked IP + 1 from YouTube
        assert stats.forwarded_packets == stats.total_packets - stats.dropped_packets
        assert "YOUTUBE" in stats.app_counts
        assert "NETFLIX" in stats.app_counts
        assert "FACEBOOK" in stats.app_counts

        # Confirm filtered PCAP contains forwarded packets
        with PcapReader(out_pcap_path) as reader:
            written_pkts = list(reader.packets())
            assert len(written_pkts) == stats.forwarded_packets
    finally:
        if os.path.exists(out_pcap_path):
            os.remove(out_pcap_path)
