"""
Créer différents paquets 
"""
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

# paquet TCP de demande de connexion
p = IP(dst='192.168.0.10')/TCP(dport=25, flags='S')

# paquet UDP de requête DNS
p = Ether(dst="00:10:de:ad:be:ef")/IP()/UDP(dport=53)