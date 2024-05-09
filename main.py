from audioop import add
import sys
import getopt

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.l2 import *
from scapy.sendrecv import send

PORTS = [80]
COUNT = 1
PROTOCOL = 4
DEBUG = False


def help_message():
    print("")
    print("Simple Net tool implemented by scapy based on Python3.")
    print("")
    print("Usage: ./main.py <cmd> <args>")
    print("")
    print("--sS/sA <IP>             TCP SYN, ACK Scan")
    print("--sn <IP>                ICMP Ping")
    print("--sU <IP>                UDP Ping")
    print("--sN/sF/sX <IP>          TCP Null, FIN, and Xmas scans")
    print("-p, --port <port>        Specific port. (Default: 80)")
    print("-c, --count <count>      Specific packet number. (Default: 1)")
    print("-6, --ipv6               Enable IPv6.")
    print("-h, --help               Print this message.")

    exit(0)


def main(argv):
    global COUNT, PORTS, PROTOCOL

    opts, _ = getopt.getopt(argv, "hp:c:6", ["help", "sn=", "sN=", "sX=", "sS=","sF=", "sU=", "sA=", "port=", "count=", "ipv6"])

    for opt, arg in opts:
        if opt in ("-p", "--port"):
            PORTS = port_spliter(arg)
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
            for port in PORTS:
                tcp_syn_scan(server_address, port)
        if opt == "--sN":
            server_address = arg
            for port in PORTS:
                tcp_null_scan(server_address, port)
        if opt == "--sA":
            server_address = arg
            for port in PORTS:
                tcp_ack_scan(server_address, port)
        if opt == "--sF":
            server_address = arg
            for port in PORTS:
                tcp_fin_scan(server_address, port)
        if opt == "--sX":
            server_address = arg
            for port in PORTS:
                tcp_xmas_scan(server_address, port)
        if opt == "--sU":
            server_address = arg
            for port in PORTS:
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
    print("Sending TCP SYN request to", address, port)

    result, _ = send_tcp_pkt(address, port, "S")

    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        elif result[0][1][1].flags in ("PA", "A", "SA"):
            print("ACK! Open!")
    else:
        print("No response after 5s. Closed!")


def tcp_ack_scan(address, port):
    print("Sending TCP SYN request to", address, port)

    result, _ = send_tcp_pkt(address, port, "A")

    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed or Out-Of-Sync!")
        else:
            print("Filtered?")
    else:
        print("Filtered?")


def tcp_null_scan(address, port):
    print("Sending TCP NULL request to", address, port)

    result, _ = send_tcp_pkt(address, port, "")
    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        else:
            print("No response! Open!")
    else:
        print("No response! Open!")


def tcp_fin_scan(address, port):
    print("Sending TCP NULL request to", address, port)
    
    result, _ = send_tcp_pkt(address, port, "F")
    if len(result) > 0:
        if result[0][1][1].flags in ("RA", "R"):
            print("RST! Closed!")
        else:
            print("No response! Open!")
    else:
        print("No response! Open!")


def tcp_xmas_scan(address, port):
    print("Sending TCP NULL request to", address, port)
    
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


def port_spliter(data):
    ports = set()

    # split , first
    ports_with_dash = data.split(",")

    for port_with_dash in ports_with_dash:
        # then, split the dash -
        if "-" in port_with_dash:
            try:
                s, e = port_with_dash.split("-")
                if s > e:
                    e, s = s, e

                ports = ports.union(set(range(int(s) if int(s) >= 0 else 0, int(e) + 1 if int(e) <= 65535 else 65536)))
                
            except:
                # in case of minus ports
                pass
        else:
            if int(port_with_dash) >= 0 and int(port_with_dash) <= 65535:
                ports.add(int(port_with_dash))

    return list(ports)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        help_message()

    main(sys.argv[1:])


