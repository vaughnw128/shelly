from os import sys
from scapy.all import sr,IP,ICMP,Raw,sniff
from multiprocessing import Process
import argparse

target_connections = set()

#Variables
ICMP_ID = int(12800)
TTL = int(64)
iface = "ens18"

class Target:

    def __init__(self, join_packet):



def on_capture(packet):
    if not packet[ICMP].id == ICMP_ID:
        pass

    if not packet[Raw].load:
        pass

    icmp_packet = (packet[Raw].load).decode('utf-8', errors='ignore').replace('\n','')

    print(packet)
    print(packet[ICMP])
    print(packet[Raw].load)
    print(icmp_packet)

def sniffing():
     sniff(iface=iface, filter="icmp", prn=on_capture, store="0")


if __name__ == "__main__":
    sniffing = Process(target=sniffing)
    sniffing.start()
    print("Starting listener")
    while True:
        input("Waiting...")