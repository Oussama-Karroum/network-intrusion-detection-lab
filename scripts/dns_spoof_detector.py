#!/usr/bin/env python3
"""
dns_spoof_detector.py

Real-time DNS spoofing detector based on Layer2/Layer3 inconsistency:
flags any DNS response that claims to originate from the legitimate
gateway IP but whose Ethernet source MAC does not match the gateway's
known MAC address. This catches spoofed responses even when the
attacker returns only a single forged reply (no duplicate-response
heuristic required).

Deployed as a systemd service (dns-spoof-detector.service) on the
Wazuh/Ubuntu host for continuous, unattended monitoring.

Source: transcribed from the project report (Chapter 5).
"""

from scapy.all import sniff, DNS, DNSRR, IP, Ether
import syslog

REAL_GATEWAY_IP = "192.168.0.1"
REAL_GATEWAY_MAC = "00:50:56:c0:00:01"  # confirmed legit gateway MAC

syslog.openlog("dns-spoof-detector", syslog.LOG_PID, syslog.LOG_LOCAL0)


def handle_packet(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
        src_ip = pkt[IP].src
        src_mac = pkt[Ether].src

        if src_ip == REAL_GATEWAY_IP and src_mac.lower() != REAL_GATEWAY_MAC.lower():
            qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else "unknown"
            answer_ip = pkt[DNSRR].rdata if pkt[DNSRR].type == 1 else "non-A record"

            msg = (f"DNS SPOOFING DETECTED: query={qname} "
                   f"fake_answer={answer_ip} "
                   f"claimed_src_ip={src_ip} "
                   f"actual_src_mac={src_mac} "
                   f"expected_mac={REAL_GATEWAY_MAC}")

            print(msg)
            syslog.syslog(syslog.LOG_ALERT, msg)


print(f"[*] Watching for DNS responses claiming to be from {REAL_GATEWAY_IP} "
      f"but not sent by MAC {REAL_GATEWAY_MAC}...")
sniff(filter="udp port 53", prn=handle_packet, store=0, iface="ens37")
