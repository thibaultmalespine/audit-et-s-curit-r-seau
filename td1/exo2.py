"""
Afficher les communications TCP qui s'établissent dans un réseau avec :
    - la source
    - la destination
    - le service

Utiliser l'annuaire inversé, fourni par : 
MY_TCP_SERVICES = {}
for proto in TCP_SERVICES.keys():
    MY_TCP_SERVICES[TCP_SERVICES[proto]] = proto
"""

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP


"""
Bonus : reverse DNS
"""

import ipaddress
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR 


def reverse_dns(ip):
    rev = ipaddress.ip_address(ip).reverse_pointer

    pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=rev, qtype="PTR"))

    rep = sr1(pkt, verbose=0, timeout=2)

    if rep and DNS in rep and rep[DNS].ancount > 0:
        print(rep[DNS].an.rdata.decode())
    else:
        print("Aucun nom trouvé")


def traiter_trame(t):
    if (TCP in t) and (t[TCP].flags == "SA"):         
        adresse_source = t[Ether].src
        adresse_destination = t[Ether].dst
        service_port = t[TCP].sport

        print(adresse_source)
        print(adresse_destination)
        print(TCP_SERVICES[service_port])
        reverse_dns(t[IP].src)

sniff(count=1000, prn=traiter_trame, iface="wlp4s0")
