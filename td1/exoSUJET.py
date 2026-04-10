from scapy.all import * 
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

def traiter_trame(t):
    if((ICMP in t) and (len(t[ICMP]) > 64)):
        print("IP émetteur : "+t[IP].src)
        print("MAC émetteur : "+t[Ether].src)
        print("Interface du tunnel : " + t[IP].dst)
sniff(prn=traiter_trame, iface="wlp4s0")