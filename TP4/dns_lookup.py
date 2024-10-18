from scapy.all import Ether, IP, UDP, DNS, DNSQR, srp

eth = Ether()


ip = IP(src="10.33.73.76", dst="8.8.8.8")


udp = UDP(sport=12345, dport=53)

dns = DNS(rd=1, qd=DNSQR(qname="ynov.com"))


frame = eth / ip / udp / dns

answered, unanswered = srp(frame, timeout=5)

if answered:
    print(answered[0][1].show())
else:
    print("Pas de réponse DNS reçue.")
