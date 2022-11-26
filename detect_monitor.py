from scapy.all import *
import psutil

IFACE = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"
IFACE_LO = "Software Loopback Interface 1"

def floodingICMP():
    PACKET = IP(dst="127.0.0.1")/ICMP()
    count = 0
    while(count < 10000):
        send(PACKET,iface=IFACE_LO,verbose = 0)
        count += 1
    print("done")



def sniffingPacket():
    capture = sniff(filter="icmp",iface=IFACE_LO,count = 10)
    print(capture.summary())

def getCPUStats():
    while(True):
        print(psutil.cpu_percent(1,percpu=True))
        # print(psutil.virtual_memory()[2])


task1 = Thread(target=sniffingPacket)
# task2 = Thread(target=floodingICMP)
task3 = Thread(target=getCPUStats)
task1.start()
# task2.start()
task3.start()


