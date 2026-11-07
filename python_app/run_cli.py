#!/usr/bin/env python3
"""
CLI entry point for the DPI Engine.
Run:
    python run_cli.py <input.pcap> [output.pcap] [--block-app YOUTUBE] [--block-ip 192.168.1.50] [--block-domain *.netflix.com]
"""
import sys
import argparse
from app.types import AppType
from app.rule_manager import RuleManager
from app.dpi_engine import DpiEngine


def main():
    parser = argparse.ArgumentParser(description="Deep Packet Inspection (DPI) Engine CLI")
    parser.add_argument("input_pcap", help="Path to input .pcap file")
    parser.add_argument("output_pcap", nargs="?", default=None, help="Optional path to output filtered .pcap file")
    parser.add_argument("--block-app", action="append", default=[], help="Application type to block (e.g. YOUTUBE, FACEBOOK)")
    parser.add_argument("--block-domain", action="append", default=[], help="Domain or wildcard to block (e.g. *.netflix.com)")
    parser.add_argument("--block-ip", action="append", default=[], help="IP address to block (e.g. 192.168.1.50)")
    parser.add_argument("--block-port", action="append", type=int, default=[], help="Port number to block (e.g. 80)")

    args = parser.parse_args()

    rules = RuleManager()
    for app_name in args.block_app:
        try:
            rules.block_app(AppType(app_name.upper()))
        except ValueError:
            print(f"Warning: Unknown application type '{app_name}'")

    for domain in args.block_domain:
        rules.block_domain(domain)

    for ip in args.block_ip:
        rules.block_ip(ip)

    for port in args.block_port:
        rules.block_port(port)

    engine = DpiEngine(rule_manager=rules)
    print(f"Inspecting PCAP: {args.input_pcap}")
    if args.output_pcap:
        print(f"Filtering output to: {args.output_pcap}")

    engine.process_pcap(args.input_pcap, output_pcap_path=args.output_pcap)
    print("\n" + engine.generate_report())


if __name__ == "__main__":
    main()
