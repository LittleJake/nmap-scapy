# nmap-scapy
nmap-scapy



## Example

```bash

Simple Net tool implemented by scapy based on Python3.

Usage: pyhton3 main.py <cmd> <args>

--sS/sA <IP>             TCP SYN, ACK Scan
--sn <IP>                ICMP Ping
--sU <IP>                UDP Ping
--sN/sF/sX <IP>          TCP Null, FIN, and Xmas scans
-p, --port <port>        Specific port. (Default: 80)
   Ex: -p 22; -p 1-65535;
-c, --count <count>      Specific packet number. (Default: 1)
-6, --ipv6               Enable IPv6.
-h, --help               Print this message.

```
