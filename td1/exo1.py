"""
Programme qui permet de sniffer un réseau et de faire la liste des adresses MAC trouvées 
sniff 10 paquets
print les adresses trouvées
"""

from scapy.all import *
from scapy.layers.l2 import Ether

liste_adresses_mac = []

def traiter_trame(t):
    if Ether in t:
        ad_mac_source = t[Ether].src
        ad_mac_destination = t[Ether].dst
        if ad_mac_source not in liste_adresses_mac:
            print(ad_mac_source)
            liste_adresses_mac.append(ad_mac_source)
        if ad_mac_destination not in liste_adresses_mac:
            print(ad_mac_destination)
            liste_adresses_mac.append(ad_mac_destination)

sniff(count= 10, prn=traiter_trame)