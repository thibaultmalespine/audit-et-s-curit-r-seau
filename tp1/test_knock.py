from scapy.all import *
from scapy.layers.inet import TCP, IP
import time


"""
Fichier de test pour le serveur de Port Knocking (exo3.py)
Ce script envoie la séquence de knock sur les bons ports, puis tente de se connecter au port protégé.
"""

# Configuration
source_ip = "127.0.54.1"  # Adresse source des paquets
target_ip = "127.0.0.1"  # Localhost pour tester sur la même machine
protected_port = 16400
knock_sequence = [2027, 3230, 2001, 17377]

print(f"[*] Test du Port Knocking")
print(f"[*] Adresse source : {source_ip}")
print(f"[*] Adresse destination : {target_ip}")
print(f"[*] Séquence de ports : {knock_sequence}")
print(f"[*] Port protégé : {protected_port}")
print()

# Étape 1 : Envoyer la séquence de port knocking
print("[*] Envoi de la séquence de port knocking...")
for i, port in enumerate(knock_sequence, 1):
    print(f"    [{i}/{len(knock_sequence)}] Knock sur le port {port}")
    # Envoyer un paquet SYN
    ip_layer = IP(src=source_ip, dst=target_ip)
    tcp_layer = TCP(dport=port, flags="S", sport=RandShort())
    pkt = ip_layer / tcp_layer
    send(pkt, verbose=False)

print("[*] Séquence de knocking envoyée!")
print()

# Attendre un peu pour que le serveur traite la séquence
time.sleep(2)

# Étape 2 : Tester la connexion au port protégé
print(f"[*] Tentative de connexion au port protégé {protected_port}...")
try:
    # Envoyer un SYN avec la même IP source
    ip_layer = IP(src=source_ip, dst=target_ip)
    tcp_layer = TCP(dport=protected_port, flags="S", sport=RandShort())
    pkt = ip_layer / tcp_layer
    
    response = sr1(pkt, timeout=3, verbose=False)
    
    if response and response.haslayer(TCP):
        if response[TCP].flags == 'SA':  # SYN-ACK reçu
            print(f"[✓] SUCCÈS : Connexion au port {protected_port} autorisée!")
            print(f"    Réponse : SYN-ACK reçu")
            # Envoyer un RST pour fermer proprement
            rst = IP(src=source_ip, dst=target_ip)/TCP(sport=response[TCP].dport, dport=protected_port, flags="R", seq=response[TCP].ack)
            send(rst, verbose=False)
        elif response[TCP].flags == 'RA':  # RST-ACK reçu
            print(f"[✗] ÉCHEC : Connexion rejetée (RST-ACK)")
    else:
        print(f"[✗] ÉCHEC : Aucune réponse reçue")
except Exception as e:
    print(f"[✗] ERREUR : {e}")

print()
print("[*] Test terminé.")
