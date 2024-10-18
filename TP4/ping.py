from scapy.all import *

ping = IP(dst="10.33.73.81")/ICMP()
response = sr1(ping, timeout=10)

if response:
    print("Pong reçu :", response.summary())
else:
    print("Aucune réponse reçue")