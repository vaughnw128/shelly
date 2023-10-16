#!/usr/bin/python3

from scapy.all import sniff
import base64
from shellylib import Host
from tinydb import TinyDB, Query
import os
import time
from itertools import count, filterfalse
import sched

TTL = int(64)
ICMP_ID = int(12800)

class Daemon(Host):
    
    def __init__(self):
        super().__init__()
        if os.path.exists('./db.json'):
            os.remove('./db.json')
        self.db = TinyDB('./db.json')

    def join(self, shellpack):
        targets = self.db.all()
        number = [target['number'] for target in targets]

        target = {
            "number": next(filterfalse(set(number).__contains__, count(1))),
            "id": shellpack['id'],
            "ip": shellpack['ip'],
            "location": shellpack['data'].decode(),
            "status": "CONNECTED"
            }

        print(f"[JOIN] Join received from {shellpack['ip']}")

        self.db.insert(target)
        
    def heartbeat(self, scheduler):
        # schedule the next call first
        scheduler.enter(60, 1, self.heartbeat, (scheduler,))
        print("Doing stuff...")
        # then do your stuff

if __name__ == "__main__":

    print("[ Starting Shelly daemon ]")
    shellyd = Daemon()
    print(shellyd)

    print("[ Starting heartbeat ]")
    heartbeat_schedule = sched.scheduler(time.time, time.sleep)
    heartbeat_schedule.enter(60, 1, shellyd.heartbeat, (heartbeat_schedule,))
    heartbeat_schedule.run()

    print("[ Starting sniffer ]")
    print("[ Shellpack log ]")
    sniff(iface=shellyd.iface, filter="icmp", prn=shellyd.sniff_callback, store="0")
