## TP4 SECU : Exfiltration

ping vers la passerelle de l'école 
```powershell
from scapy.all import *

ping = ICMP(type=8)


packet = IP(src="10.33.73.76", dst="10.33.79.254")


frame = Ether(src="e0-0a-f6-b0-73-d5", dst=" 7c-5a-1c-d3-d8-76")


final_frame = frame/packet/ping


answers, unanswered_packets = srp(final_frame, timeout=10)


print(f"Pong reçu : {[unanswered_packets[0]]}")
print(f"Pong reçu : {answers}")



Pong reçu : [<Ether  dst= 7c-5a-1c-d3-d8-76 src=e0-0a-f6-b0-73-d5 type=IPv4 |<IP  frag=0 proto=icmp src=10.33.73.76 dst=10.33.79.254 |<ICMP  type=echo-request |>>>]

Pong reçu : <Results: TCP:0 UDP:0 ICMP:0 Other:0>
```
````bash
from scapy.all import *

ping = IP(dst="10.33.73.81")/ICMP()
response = sr1(ping, timeout=10)

if response:
    print("Pong reçu :", response.summary())
else:
    print("Aucune réponse reçue")



Received 4 packets, got 1 answers, remaining 0 packets
Pong reçu : IP / ICMP 10.33.73.81 > 10.33.73.76 echo-reply 0
```