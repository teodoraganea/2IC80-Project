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
        
    