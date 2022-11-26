import subprocess, ctypes, os, sys
from scapy.all import *
import time

def addRule(rule_name,ip):
    os.popen('netsh advfirewall firewall add rule name="'+rule_name +'" dir=in action=block localip='+ ip + ' remoteip=' + ip)
    os.popen("netsh advfirewall firewall set rule name="+ rule_name +" new enable=yes")







def calculate_pi(pck,list):
    srcIp = pck.getlayer(IP).src
    count  = 0
    for pck in list:
        if(pck.getlayer(IP).src == srcIp):
            count += 1
    return 1/count


def calculate_Entropy(list) -> float:
    sum = 0
    for pck in list:
        pi =  calculate_pi(pck,list)
        sum += pi*math.log2(pi)
    return -sum



start_time = time.time()
list_pck = []
def filter_icmp(pck):
    count = 0
    global start_time
    global list_pck
    if(IP in pck):
        
        list_pck.append(pck)
        print(time.time() -start_time)
        if(time.time() - start_time > 2 and len(list_pck) > 10):
            entropy = calculate_Entropy(list_pck)
            print(entropy)
            list_pck.clear()
            start_time = time.time()
        if(ICMP in pck and str(pck.getlayer(ICMP).type)=="8"):
            count += 1
            print(pck.summary())
            if(count == 1):
                ip = pck.getlayer(IP).src
                print(ip)
                addRule("Block Attack",ip)
               
            





sniffer =AsyncSniffer(prn=lambda x: filter_icmp(x), store=0)
sniffer.start()

while True:
    time.sleep(1)


