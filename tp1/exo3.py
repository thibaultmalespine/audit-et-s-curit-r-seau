from scapy.all import *
from scapy.layers.inet import TCP, IP
import subprocess


"""
Réalisation d’un serveur de « Port Knocking ».
"""

# ajouter REJECT seulement si absent
def add_reject():
    r = subprocess.run([
        "iptables","-C","INPUT",
        "-p","tcp","--dport","16400",
        "-j","REJECT","--reject-with","tcp-reset"
    ])

    if r.returncode != 0:
        subprocess.run([
            "iptables","-A","INPUT",
            "-p","tcp","--dport","16400",
            "-j","REJECT","--reject-with","tcp-reset"
        ])

add_reject()

port_knocking_port = [2027, 3230, 2001, 17377]
attempt = {}

def traiter_trame(t):

    # Vérifier la demande de connexion (flag S) et la présence de TCP dans la trame
    if TCP not in t or t[TCP].flags != 'S':
        return
    
    
    ip = t[IP].src

    if ip not in attempt:
        attempt[ip] = [0,0,0,0]
        
    else :
        # Vérifier si le port n'est pas déjà le dernier enregistré (éviter les doublons)
        if attempt[t[IP].src][-1] == t[TCP].dport:
            return

        attempt[ip].pop(0)
        attempt[ip].append(t[TCP].dport)  

        if attempt[ip] == port_knocking_port :
            print("séquence correct !")
            subprocess.run([
                "iptables","-D","INPUT",
                "-p","tcp","--dport","16400",
                "-j","REJECT","--reject-with","tcp-reset"
            ])



sniff(iface="lo", timeout=100, prn=traiter_trame, filter="tcp")