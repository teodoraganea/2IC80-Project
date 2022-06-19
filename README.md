# 2IC80 - Default Project, Group 48

This represents a fully-fledged, automated Python tool which performs three MITM attacks: ARP Poisoning, DNS Spoofing and SSL Stripping.

## Mechanisms
The project runs on Oracle VM VirtualBox environment. For this, all three machines need to be running. M3 is the attacker, while M1 and M2 are the two
endpoints instantiating communication. M1 is the victim and operates on WindowsXP, whereas M2 is the server.

## Running the application
 After opening all three virtual machines, the user should perform the following on M3:
   1. Install Scapy Python library and Tkinter Python library
   2. In its terminal, write `sudo su` command
   3. Write `sysctl net.ipv4.ip_forward=0` command
   4. Indicate the directory of the project files
   5. Write `sudo python main.py` to start the program. This makes the GUI appear.
   6. Follow the instructions for each attack, first by performing ARP Poisoning
  
  To check if the poisoning started, open Command Prompt for M1 and type `arp -a` to inspect the victim's ARP table.





