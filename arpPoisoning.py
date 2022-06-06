from scapy.all import *
import threading
from tkinter import*
import sys
import os

class arpPoisoning():

    def __init__(self, interface, root):
        self.interface = interface
        self.root = root