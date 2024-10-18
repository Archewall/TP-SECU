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
