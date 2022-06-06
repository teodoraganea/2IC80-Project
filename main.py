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


def initIterface(modeType):
    global interface
    interface = modeType
    destrWidget()
    initiate()


def chooseInterface():
    Label(root, text='Choose the interface: enp0s3->arp enp0s8->DNS').pack()
    OPTIONS = get_if_list()  # etc
    selectMode = Listbox(root, selectmode="single", width=100)
    for each_item in range(len(OPTIONS)):
        selectMode.insert(END, OPTIONS[each_item])
    selectMode.pack()

    def selected():
        itemsInListebox = selectMode.get(0, END)
        indexesfSelectedItems = selectMode.curselection()  # tuple with indexes of selected items
        list = [itemsInListebox[item] for item in indexesfSelectedItems]
        selectedMode = list[0]
        initIterface(selectedMode)

    Button(root, text="Execute", command=selected).pack()

def dnsButton():
    destrWidget()
    global mode
    mode = "dns"
    chooseInterface()

def arpButton():
    destrWidget()
    global mode
    mode = "arp"
    chooseInterface()

def sslButton():
    destrWidget()
    global mode
    mode = "ssl"
    chooseInterface()

def destrWidget():
    for widget in root.winfo_children():
        widget.destroy()
