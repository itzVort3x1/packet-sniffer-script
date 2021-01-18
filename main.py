#!/usr/bin/env/ python
import scapy.all as scapy


def sniff(interface):
    #setting store to False wont store the packets in the computer's local storage
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    print(packet)


sniff("eth0")