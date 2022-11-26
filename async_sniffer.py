from scapy.all import *
import psutil




def getCPUStats():
    while(True):
        print(psutil.cpu_percent(1,percpu=True))
        # print(psutil.virtual_memory()[2])


sniffer =AsyncSniffer(prn=lambda x: print(x.summary()), store=False,filter="icmp")
sniffer.start()
while True:
    time.sleep(1)