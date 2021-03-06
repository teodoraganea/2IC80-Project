from scapy.all import *
from dnsSpoofing import dnsSpoofing
from arpPoisoning import arpPoisoning
from Tkinter import*
import threading
from sslStrip import sslStrip

root = Tk()
root.geometry('600x400')
root.title('ARP_DNS_SSL')

mode = ""
interface = ""

def start():
    proc_thread = None
    if mode == "arp":
        process = arpPoisoning(interface, root)
        process.getInput()
    elif mode == "dns":
        process = dnsSpoofing(interface, root)
        process.getInput()
    elif mode == "ssl":
        process = sslStrip(interface, root) #dnsSpoofing(interface, root)
        process.getInput()
    else:
        print("Error")


def beforeInit(modeType):
    global interface
    interface = modeType
    destroy()
    start()


def interfaceSelection():
    Label(root, text='Select the interface').pack()
    Label(root, text='If a NAT network is present, choose enp0s8').pack()
    options = get_if_list() 
    selectMode = Listbox(root, selectmode="single", width=30)
    for each_item in range(len(options)):
        selectMode.insert(END, options[each_item])
    selectMode.pack()

    def select():
        itemsInListbox = selectMode.get(0, END)  
        indexesOfSelectedItems = selectMode.curselection()
        list = [itemsInListbox[item] for item in indexesOfSelectedItems]
        selectedMode = list[0]
        beforeInit(selectedMode)

    Button(root, text="Execute", command=select).pack()



def dnsButton():
    destroy()
    global mode
    mode = "dns"
    interfaceSelection()


def arpButton():
    destroy()
    global mode
    mode = "arp"
    interfaceSelection()

def sslButton():
    destroy()
    global mode
    mode = "ssl"
    interfaceSelection()

def destroy():
    for widget in root.winfo_children():
        widget.destroy()

entry = Label(root, text='Select the attack').place(relx=0.5, rely=0.2, anchor='center')
dnsButton = Button(root, text="DNS spoofing", command=dnsButton).place(relx=0.5, rely=0.5, anchor='center')
arpButton = Button(root, text="ARP poisoning", command=arpButton).place(relx=0.3, rely=0.5, anchor='center')
arpButton = Button(root, text="SSL strip", command=sslButton).place(relx=0.7, rely=0.5, anchor='center')

root.mainloop()
