from scapy.all import *
from tkinter import *

root = Tk()
root.geometry('600x400')
root.title('ARP_DNS_SSL')

mode = ""
interface = ""

def initiate():
    if mode == "arp":
        process = arp(interface, root)
        process.get_IP()
    elif mode == "dns":
        process = dnsPoisoning(interface, root)
        process.get_IP()
    elif mode == "ssl":
        process = SSLstrip(interface, root)
        process.get_IP()
    else:
        print("Wrong initiation")
