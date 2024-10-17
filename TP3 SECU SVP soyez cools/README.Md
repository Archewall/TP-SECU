# TP3 SECU : SVP soyez cools

## Carte de tout le batiment 

![Carte de tout le batiment1](/TP3/batiment_ynov.jpg)  
![Carte de tout le batiment2](/TP3/batiment_ynov_2.jpg)  
![Carte de tout le batiment3](/TP3/batiment_ynov_3.jpg)  
![Carte de tout le batiment4](/TP3/batiment_ynov_4.jpg)

## Fika
### Télé iiyama : 
```
  Adresse mac : GuangzhouShi_b7:53:ba (f4:20:15:b7:53:ba)
  Ipv6 : fe80::f908:194:88b3:f34a
  Ipv4 : 10.33.81.227
```

**Après avoir conf un serveur dhcp pour attribuer une ip a notre télé**

```
ping 10.33.81.100

Envoi d’une requête 'Ping'  10.33.81.100 avec 32 octets de données :
Réponse de 10.33.81.100 : octets=32 temps=2 ms TTL=64
Réponse de 10.33.81.100 : octets=32 temps=2 ms TTL=64
Réponse de 10.33.81.100 : octets=32 temps=2 ms TTL=64

Statistiques Ping pour 10.33.81.100:
    Paquets : envoyés = 3, reçus = 3, perdus = 0 (perte 0%),
Durée approximative des boucles en millisecondes :
    Minimum = 2ms, Maximum = 2ms, Moyenne = 2ms
```

```
PS C:\Users\Makhov> nmap -sS 10.33.81.100
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-11 11:10 Paris, Madrid (heure dÆÚtÚ)
Nmap scan report for 10.33.81.100
Host is up (0.00063s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
1080/tcp open  socks
1443/tcp open  ies-lm
8000/tcp open  http-alt
8600/tcp open  asterix
MAC Address: F4:20:15:B7:53:BA (Guangzhou Shiyuan Electronic Technology Company Limited)

Nmap done: 1 IP address (1 host up) scanned in 2.06 seconds
```

```
 nmap -O 10.33.81.100
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-11 11:13 Paris, Madrid (heure dÆÚtÚ)
Nmap scan report for 10.33.81.100
Host is up (0.0011s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
1080/tcp open  socks
1443/tcp open  ies-lm
8000/tcp open  http-alt
8600/tcp open  asterix
MAC Address: F4:20:15:B7:53:BA (Guangzhou Shiyuan Electronic Technology Company Limited)
Device type: phone
Running: Google Android 10.X, Linux 4.X
OS CPE: cpe:/o:google:android:10 cpe:/o:linux:linux_kernel:4
OS details: Android 9 - 10 (Linux 4.9 - 4.14)
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.46 seconds
```
**On peut tester chaque port ouvert et on trouve un port en particulier avec une vulnerabilité : http://10.33.81.100:1443, ou la il peut y avoir un man in the middle**


## Distributeur

**Nous nous sommes branché en ethernet notre serveur DHCP lui a attribué un IP**

```
nmap -sS 10.33.81.101

Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-11 11:36 Paris, Madrid (heure dÆÚtÚ)
Nmap scan report for 10.33.81.101
Host is up (0.0016s latency).
All 1000 scanned ports on 10.33.81.101 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 10:1E:DA:C5:D0:2F (Ingenico Terminals SAS)
```

```
nmap -O 10.33.81.101

Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-11 11:36 Paris, Madrid (heure dÆÚtÚ)
Nmap scan report for 10.33.81.101
Host is up (0.00092s latency).
All 1000 scanned ports on 10.33.81.101 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 10:1E:DA:C5:D0:2F (Ingenico Terminals SAS)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.21 seconds
```

## Lister toutes les adresses MAC et IP du réseau

```
nmap -sn 10.33.73.0/24
Starting Nmap 7.94 ( https://nmap.org ) at 2024-10-11 12:16 Paris, Madrid (heure d’été)
Nmap scan report for 10.33.73.0
Host is up (0.020s latency).
MAC Address: F4:C8:8A:E2:B6:BB (Intel Corporate)
Nmap scan report for 10.33.73.3
Host is up (0.0080s latency).
MAC Address: 10:68:38:3F:A6:E5 (Unknown)
Nmap scan report for 10.33.73.5
Host is up (0.046s latency).
MAC Address: 68:7A:64:84:DB:9F (Intel Corporate)
Nmap scan report for 10.33.73.6
Host is up (0.0060s latency).
MAC Address: 10:6F:D9:4E:21:11 (Cloud Network Technology Singapore PTE.)
Nmap scan report for 10.33.73.7
Host is up (0.087s latency).
MAC Address: 48:E7:DA:58:7C:03 (AzureWave Technology)
Nmap scan report for 10.33.73.8
Host is up (0.55s latency).
MAC Address: 84:94:37:D9:9F:FB (Unknown)
Nmap scan report for 10.33.73.9
Host is up (0.0040s latency).
MAC Address: 84:1B:77:FD:5C:A0 (Intel Corporate)
Nmap scan report for 10.33.73.11
Host is up (0.046s latency).
MAC Address: 10:68:38:CC:E0:A2 (Unknown)
Nmap scan report for 10.33.73.12
Host is up (0.019s latency).
MAC Address: D4:3B:04:A7:5A:A8 (Intel Corporate)
Nmap scan report for 10.33.73.17
Host is up (0.0050s latency).
MAC Address: 3C:21:9C:5A:5D:20 (Intel Corporate)
Nmap scan report for 10.33.73.46
Host is up (0.0060s latency).
MAC Address: C8:89:F3:E7:69:9F (Apple)
Nmap scan report for 10.33.73.50
Host is up (0.0090s latency).
MAC Address: 28:6B:35:F2:3E:24 (Intel Corporate)
Nmap scan report for 10.33.73.58
Host is up (0.12s latency).
MAC Address: F2:43:93:AA:49:D3 (Unknown)
Nmap scan report for 10.33.73.59
Host is up (0.0080s latency).
MAC Address: 98:59:7A:99:C1:9A (Intel Corporate)
Nmap scan report for 10.33.73.65
Host is up (0.82s latency).
MAC Address: BE:8B:4A:37:4A:3F (Unknown)
Nmap scan report for 10.33.73.67
Host is up (0.066s latency).
MAC Address: 72:8C:8E:71:6C:79 (Unknown)
Nmap scan report for 10.33.73.71
Host is up (0.0040s latency).
MAC Address: 40:1A:58:3B:37:EC (Wistron Neweb)
Nmap scan report for 10.33.73.75
Host is up (0.0060s latency).
MAC Address: 70:D8:23:5E:1B:C2 (Intel Corporate)
Nmap scan report for 10.33.73.76
Host is up (0.0060s latency).
MAC Address: E0:0A:F6:B0:73:D5 (Liteon Technology)
Nmap scan report for 10.33.73.77
Host is up (0.0050s latency).
MAC Address: 98:8D:46:C4:FA:E5 (Intel Corporate)
Nmap scan report for 10.33.73.82
Host is up (0.0080s latency).
MAC Address: 40:1A:58:4B:44:84 (Wistron Neweb)
Nmap scan report for 10.33.73.84
Host is up (0.078s latency).
MAC Address: 8A:71:40:AE:93:F6 (Unknown)
Nmap scan report for 10.33.73.86
Host is up (0.0050s latency).
MAC Address: EA:7D:42:FE:CB:AF (Unknown)
Nmap scan report for 10.33.73.93
Host is up (0.0070s latency).
MAC Address: 98:59:7A:C9:37:2C (Intel Corporate)
Nmap scan report for 10.33.73.95
Host is up (0.0050s latency).
MAC Address: F4:C8:8A:72:7C:FC (Intel Corporate)
Nmap scan report for 10.33.73.96
Host is up (0.0050s latency).
MAC Address: 2C:0D:A7:AE:5A:15 (Intel Corporate)
Nmap scan report for 10.33.73.98
Host is up (0.11s latency).
MAC Address: 38:7A:0E:C6:72:0D (Intel Corporate)
Nmap scan report for 10.33.73.100
Host is up (0.057s latency).
MAC Address: B0:A4:60:CB:57:50 (Intel Corporate)
Nmap scan report for 10.33.73.101
Host is up (0.056s latency).
MAC Address: 20:2B:20:BF:13:EB (Cloud Network Technology Singapore PTE.)
Nmap scan report for 10.33.73.105
Host is up (0.048s latency).
MAC Address: F8:B5:4D:ED:9D:3D (Intel Corporate)
Nmap scan report for 10.33.73.108
Host is up (0.096s latency).
MAC Address: DC:46:28:A4:9A:48 (Intel Corporate)
Nmap scan report for 10.33.73.109
Host is up (0.048s latency).
MAC Address: A4:F9:33:12:52:9B (Intel Corporate)
Nmap scan report for 10.33.73.110
Host is up (0.095s latency).
MAC Address: 20:2B:20:BF:43:33 (Cloud Network Technology Singapore PTE.)
Nmap scan report for 10.33.73.112
Host is up (0.044s latency).
MAC Address: F4:C8:8A:6F:09:DC (Intel Corporate)
Nmap scan report for 10.33.73.113
Host is up (0.093s latency).
MAC Address: 04:E8:B9:5C:4E:FF (Intel Corporate)
Nmap scan report for 10.33.73.118
Host is up (0.040s latency).
MAC Address: 50:5A:65:4F:B8:61 (AzureWave Technologies)
Nmap scan report for 10.33.73.120
Host is up (0.088s latency).
MAC Address: 70:D8:23:29:F9:78 (Intel Corporate)
Nmap scan report for 10.33.73.121
Host is up (0.042s latency).
MAC Address: 04:E8:B9:D6:07:86 (Intel Corporate)
Nmap scan report for 10.33.73.127
Host is up (0.49s latency).
MAC Address: A4:9B:4F:0D:65:F1 (Huawei Technologies)
Nmap scan report for 10.33.73.129
Host is up (0.085s latency).
MAC Address: 32:A3:7F:18:55:E1 (Unknown)
Nmap scan report for 10.33.73.130
Host is up (0.12s latency).
MAC Address: A6:A5:EC:36:7D:56 (Unknown)
Nmap scan report for 10.33.73.132
Host is up (0.12s latency).
MAC Address: 1C:57:DC:2F:E9:D8 (Apple)
Nmap scan report for 10.33.73.133
Host is up (0.52s latency).
MAC Address: D2:BA:61:44:F4:2F (Unknown)
Nmap scan report for 10.33.73.134
Host is up (0.022s latency).
MAC Address: 2C:3B:70:73:68:0B (AzureWave Technology)
Nmap scan report for 10.33.73.136
Host is up (0.025s latency).
MAC Address: 2A:C9:95:A7:52:B0 (Unknown)
Nmap scan report for 10.33.73.139
Host is up (0.20s latency).
MAC Address: 16:9A:2C:BD:77:E9 (Unknown)
Nmap scan report for 10.33.73.140
Host is up (0.11s latency).
MAC Address: CA:5E:25:3C:89:B2 (Unknown)
Nmap scan report for 10.33.73.144
Host is up (0.015s latency).
MAC Address: F8:FF:C2:24:B5:91 (Apple)
Nmap scan report for 10.33.73.151
Host is up (1.5s latency).
MAC Address: 72:94:F2:8E:C8:36 (Unknown)
Nmap scan report for 10.33.73.156
Host is up (0.10s latency).
MAC Address: 0A:76:3D:40:4D:84 (Unknown)
Nmap scan report for 10.33.73.159
Host is up (0.0070s latency).
MAC Address: FE:92:CC:26:0E:B3 (Unknown)
Nmap scan report for 10.33.73.172
Host is up (1.2s latency).
MAC Address: 1A:C9:C9:0B:4D:4E (Unknown)
Nmap scan report for 10.33.73.177
Host is up (0.042s latency).
MAC Address: F2:8F:65:58:27:9F (Unknown)
Nmap scan report for 10.33.73.178
Host is up (0.11s latency).
MAC Address: 7A:8C:0D:C5:CC:D0 (Unknown)
Nmap scan report for 10.33.73.181
Host is up (0.17s latency).
MAC Address: 62:02:C7:72:0A:D5 (Unknown)
Nmap scan report for 10.33.73.185
Host is up (0.72s latency).
MAC Address: 5A:BF:F4:CF:1D:C8 (Unknown)
Nmap scan report for 10.33.73.189
Host is up (0.13s latency).
MAC Address: E6:30:E0:BC:03:6D (Unknown)
Nmap scan report for 10.33.73.191
Host is up (0.32s latency).
MAC Address: 5E:D2:04:49:6C:79 (Unknown)
Nmap scan report for 10.33.73.193
Host is up (0.0060s latency).
MAC Address: E4:0D:36:30:E9:AE (Intel Corporate)
Nmap scan report for 10.33.73.194
Host is up (0.059s latency).
MAC Address: 76:AC:82:34:87:8E (Unknown)
Nmap scan report for 10.33.73.195
Host is up (0.72s latency).
MAC Address: 9A:F0:C2:E5:3A:20 (Unknown)
Nmap scan report for 10.33.73.199
Host is up (0.0050s latency).
MAC Address: 30:89:4A:0F:4F:1A (Intel Corporate)
Nmap scan report for 10.33.73.200
Host is up (0.037s latency).
MAC Address: 82:91:8D:83:74:2F (Unknown)
Nmap scan report for 10.33.73.201
Host is up (0.057s latency).
MAC Address: 66:8E:B3:3E:90:A4 (Unknown)
Nmap scan report for 10.33.73.202
Host is up (0.056s latency).
MAC Address: 86:A4:8F:A0:56:92 (Unknown)
Nmap scan report for 10.33.73.203
Host is up (0.027s latency).
MAC Address: 22:0F:D4:63:7C:69 (Unknown)
Nmap scan report for 10.33.73.204
Host is up (0.34s latency).
MAC Address: 0E:78:75:D7:CA:FA (Unknown)
Nmap scan report for 10.33.73.205
Host is up (0.10s latency).
MAC Address: 1C:57:DC:35:1C:6E (Apple)
Nmap scan report for 10.33.73.206
Host is up (0.076s latency).
MAC Address: DC:46:28:CD:9A:6F (Intel Corporate)
Nmap scan report for 10.33.73.214
Host is up (0.072s latency).
MAC Address: E2:A0:A6:B6:F0:50 (Unknown)
Nmap scan report for 10.33.73.215
Host is up (0.027s latency).
MAC Address: FE:36:07:84:07:9F (Unknown)
Nmap scan report for 10.33.73.216
Host is up (0.026s latency).
MAC Address: 0E:D4:65:4D:B4:3D (Unknown)
Nmap scan report for 10.33.73.218
Host is up (0.11s latency).
MAC Address: 8A:BB:06:B3:A9:23 (Unknown)
Nmap scan report for 10.33.73.219
Host is up (0.11s latency).
MAC Address: F6:99:7B:56:F4:56 (Unknown)
Nmap scan report for 10.33.73.220
Host is up (0.056s latency).
MAC Address: DA:05:79:63:C5:A5 (Unknown)
Nmap scan report for 10.33.73.224
Host is up (0.98s latency).
MAC Address: 1A:C8:CE:5D:53:61 (Unknown)
Nmap scan report for 10.33.73.232
Host is up (0.11s latency).
MAC Address: F2:20:79:DC:29:CB (Unknown)
Nmap scan report for 10.33.73.238
Host is up (0.14s latency).
MAC Address: 2A:6A:7A:32:20:74 (Unknown)
Nmap scan report for 10.33.73.240
Host is up (0.089s latency).
MAC Address: 1A:93:F7:9A:EC:E5 (Unknown)
Nmap scan report for 10.33.73.241
Host is up (0.030s latency).
MAC Address: 98:59:7A:B3:B7:C1 (Intel Corporate)
Nmap scan report for 10.33.73.244
Host is up (0.14s latency).
MAC Address: F4:BF:80:C0:A1:D3 (Huawei Technologies)
Nmap scan report for 10.33.73.252
Host is up (0.13s latency).
MAC Address: 2A:A6:0B:22:50:DC (Unknown)
Nmap scan report for 10.33.73.253
Host is up (0.60s latency).
MAC Address: B2:03:9D:BD:C5:88 (Unknown)
Nmap scan report for 10.33.73.254
Host is up (0.23s latency).
MAC Address: 52:F7:F7:73:F7:8F (Unknown)
Nmap scan report for 10.33.73.81
Host is up.
Nmap done: 256 IP addresses (85 hosts up) scanned in 12.52 seconds
```