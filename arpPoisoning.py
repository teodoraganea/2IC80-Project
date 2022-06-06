from scapy.all import *
import threading
from tkinter import*
import sys
import os

class arpPoisoning():

    def __init__(self, interface, root):
        self.interface = interface
        self.root = root

    def setInput(self, rangeIP, usedIPs, victims, maliciousServers, myMAC):
        self.rangeIP = rangeIP
        self.usedIPs = usedIPs
        self.victims = victims
        self.maliciousServers = maliciousServers
        self.myMAC = myMAC