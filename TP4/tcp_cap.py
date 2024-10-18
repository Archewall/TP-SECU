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
