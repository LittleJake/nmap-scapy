from audioop import add
import sys
import getopt

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import *
from scapy.sendrecv import send

PORT = 80
COUNT = 1
PROTOCOL = 4
DEBUG = True


def help_message():
    print("")
    print("Simple Net tool implemented by scapy based on Python3.")
    print("")
    print("Usage: ./main.py <cmd> <args>")
    print("")
    print("--sS <IP>                TCP SYN Scan")
    print("--sn <IP>                ICMP Ping")
    print("--sN/sF/sX <IP>          TCP Null, FIN, and Xmas scans")
    print("-p, --port <port>        Specific port. (Default: 80)")
    print("-c, --count <count>      Specific packet number. (Default: 1)")
    print("-6, --ipv6               Enable IPv6.")
    print("-h, --help               Print this message.")

    exit(0)


def main(argv):
    global COUNT, PORT, PROTOCOL

    opts, _ = getopt.getopt(argv, "hp:c:6", ["help", "sn=", "sN=", "sX=", "sS=","sF=", "sU=", "sA=", "port=", "count=", "ipv6"])

    for opt, arg in opts:
        if opt in ("-p", "--port"):
            PORT = int(arg)
        if opt in ("-c", "--count"):
            COUNT = int(arg)
        if opt in ("-6", "--ipv6"):
            PROTOCOL = 6

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help_message()
        if opt == "--sn":
            server_address = arg
            ping(server_address)
        if opt == "--sS":
            server_address = arg
            tcp_syn_scan(server_address, PORT)
        if opt == "--sN":
            server_address = arg
            tcp_null_scan(server_address, PORT)
        if opt == "--sA":
            server_address = arg
            tcp_ack_scan(server_address, PORT)
        if opt == "--sF":
            server_address = arg
            tcp_fin_scan(server_address, PORT)
        if opt == "--sX":
            server_address = arg
            tcp_xmas_scan(server_address, PORT)
        if opt == "--sU":
            server_address = arg
            udp_ping(server_address)


def udp_ping(address):
    print("Pinging...", address)
    if PROTOCOL == 4:
        pkt = IP(dst=address) / UDP(dport=0)
    elif PROTOCOL == 6:
        pkt = IPv6(dst=address) / UDP(dport=0)
    result, _ = sr(pkt * COUNT, timeout=5, verbose=DEBUG)
    if len(result) > 0:
        print("Pong! Alive!")
    else:
        print("No response after 5s. Dead!")



def ping(address):
    print("Pinging...", address)
    if PROTOCOL == 4:
        pkt = IP(dst=address) / ICMP()
    elif PROTOCOL == 6:
        pkt = IPv6(dst=address) / ICMP()

    result, _ = sr(pkt * COUNT, timeout=5, verbose=DEBUG)
    if len(result) > 0:
        print("Pong! Alive!")
    else:
        print("No response after 5s. Dead!")


def tcp_syn_scan(address, port):
    print("Sending TCP SYN request", address)

    result, _ = send_tcp_pkt(address, port, "S")

    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        elif result[0][1][1].flags in ("PA", "A", "SA"):
            print("ACK! Open!")
    else:
        print("No response after 5s. Closed!")


def tcp_ack_scan(address, port):
    print("Sending TCP SYN request", address)

    result, _ = send_tcp_pkt(address, port, "A")

    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed or Out-Of-Sync!")
        else:
            print("Filtered?")
    else:
        print("Filtered?")


def tcp_null_scan(address, port):
    print("Sending TCP NULL request", address)

    result, _ = send_tcp_pkt(address, port, "")
    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        else:
            print("No response! Open!")
    else:
        print("No response! Open!")


def tcp_fin_scan(address, port):
    print("Sending TCP NULL request", address)
    
    result, _ = send_tcp_pkt(address, port, "F")
    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        else:
            print("No response! Open!")
    else:
        print("No response! Open!")


def tcp_xmas_scan(address, port):
    print("Sending TCP NULL request", address)
    
    result, _ = send_tcp_pkt(address, port, "FPU")
    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        else:
            print("No response! Open!")
    else:
        print("No response! Open!")


def send_tcp_pkt(address, port, flags):
    if PROTOCOL == 4:
        pkt = IP(dst=address) / TCP(dport=port, flags=flags)
    elif PROTOCOL == 6:
        pkt = IPv6(dst=address) / TCP(dport=port, flags=flags)
        
    if DEBUG:
        print(pkt)

    return sr(pkt * COUNT, timeout=5, verbose=DEBUG)



if len(sys.argv) < 2:
    help_message()

if __name__ == '__main__':
    main(sys.argv[1:])
