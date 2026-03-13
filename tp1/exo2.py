from scapy.all import *
from scapy.layers.inet import TCP, IP


"""
Détection de trafic d’audit


Écrire un programme utilisant Scapy permettant de détecter si on est la cible d’un scannage de port, c-
à-d une succession de tentative de connexion vers des ports TCP différents dans un temps très court et pour
une même adresse IP source.
Vous prendrez les valeurs suivantes pour configurer le seuil de détection :
⊳ un intervalle de temps de 10s ;
⊳ un nombre de ports d’au moins 5
"""

ports = {}

def traiter_trame(t):
    if TCP not in t:
        return

    port = t[TCP].dport
    ip_source = t[IP].src

    if ip_source not in ports:
        ports[ip_source] = []
    else :
        if port not in ports[ip_source] : 
            ports[ip_source].append(port)

        if len(ports[ip_source]) > 5 :
            print('scan de port en cours !')

sniff(iface="lo", timeout=10, prn=traiter_trame, filter="tcp")

