## TP4 SECU : Exfiltration

### ping
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
```py
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

### TCP_cap

```py
from scapy.all import sniff, TCP, IP


def paquet_tcp_syn_ack(packet):
    
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        
        if tcp_layer.flags == 0x12:
            print("TCP SYN ACK reçu !")
            print(f"- Adresse IP src : {packet[IP].src}")
            print(f"- Adresse IP dst : {packet[IP].dst}")
            print(f"- Port TCP src : {tcp_layer.sport}")
            print(f"- Port TCP dst : {tcp_layer.dport}")
            return True  

def start_sniffing():
    print("NYA JE T'ECOUTE !")
    sniff(filter="tcp", prn=paquet_tcp_syn_ack, stop_filter=lambda x: paquet_tcp_syn_ack(x), store=0)

if __name__ == "__main__":
    start_sniffing()



NYA JE T'ECOUTE !
TCP SYN ACK reçu !
- Adresse IP src : 40.126.32.76
- Adresse IP dst : 10.33.73.76
- Port TCP src : 443
- Port TCP dst : 7521
```

### dns cap 

```py
from scapy.all import sniff, DNS, DNSQR, DNSRR


capture_done = False

def paquet_dns(packet):
    global capture_done
    
    if packet.haslayer(DNS) and not capture_done:
        dns_layer = packet[DNS]
        
        if dns_layer.opcode == 0 and dns_layer.qr == 0:  
            if dns_layer.qd.qname.decode() == "ynov.com.":
                print("J'AI CATCH YNOV")
        
        elif dns_layer.qr == 1: 
            if dns_layer.an and dns_layer.qd.qname.decode() == "ynov.com.":
                for i in range(dns_layer.ancount):
                    if isinstance(dns_layer.an[i], DNSRR) and dns_layer.an[i].type == 1:  
                        print(f"Réponse DNS capturée : {dns_layer.an[i].rdata}")
                        capture_done = True  
                        return True  

def stop_sniff(packet):
    return capture_done  


def start_sniffing():
    print("En écoute pour une requête DNS pour ynov.com...")
    sniff(filter="udp port 53", prn=paquet_dns, stop_filter=stop_sniff, store=0)

if __name__ == "__main__":
    start_sniffing()


En écoute pour une requête DNS pour ynov.com...
J'AI CATCH YNOV
Réponse DNS capturée : 172.67.74.226
True
```