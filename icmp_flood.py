from scapy.all import *


ip_packet = IP(dst="192.168.43.250")
ip_packet.src = "1.1.1.1"
icmp_packet = ICMP()
raw_packet = Raw(RandString(size=2000))


IFACE = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"
IFACE_LO = "Software Loopback Interface 1"
IFACE_LAPTOP = "Intel(R) Wi-Fi 6 AX201 160MHz"


send(ip_packet/icmp_packet/raw_packet,loop=1,iface=IFACE,verbose = 0)


