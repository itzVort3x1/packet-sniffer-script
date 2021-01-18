#!/usr/bin/env/ python
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    #setting store to False wont store the packets in the computer's local storage
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="udp")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)


sniff("eth0")