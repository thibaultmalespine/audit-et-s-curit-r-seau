from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from zlib import crc32

"""
Contrôle d’erreur

a) Les deux trames posséderont les mêmes informations suivantes :
⋄ adresse IP source : 164.81.50.10 ;
⋄ adresse IP destination : 164.81.50.20 ;
⋄ port source : 6578 ;
⋄ port destination : 7869 ;


b) Comparez les valeurs calculées des checksums présents dans la couche UDP, sont ils identiques ? Oui 
Pourquoi ? Parce que les payloads sont de même taille est que le reste des champs sont identiques


c) Calculez le CRC-32 de chacune de ces trames : sont-ils différents ? Pourquoi ?
Oui, parce que le timestamp n'est pas le même entre la construction des deux paquets
"""

# 1- Paquet UDP contenant b'\x00\x00' 

udp = Ether()/IP(src="164.81.50.10", dst="164.81.50.20")/UDP(sport=6578, dport=7869)/Raw(load=b'\x00\x00')
pkt = Ether(bytes(udp))   # reconstruction -> calcul des champs
pkt.show()

raw = bytes(udp) # représentation binaire du paquet
print(crc32(raw))

# 2 - Paquet UDP contenant b'\xFF\xFF

udp = Ether()/IP(src="164.81.50.10", dst="164.81.50.20")/UDP(sport=6578, dport=7869)/Raw(load=b'\xFF\xFF')
pkt = Ether(bytes(udp))   # reconstruction -> calcul des champs
pkt.show()

raw = bytes(udp) # représentation binaire du paquet
print(crc32(raw))
