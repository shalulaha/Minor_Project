from tkinter import Tk, Canvas, Text, Scrollbar, Label
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import socket
import time
from datetime import datetime

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception as e:
        local_ip = "Unable to determine local IP"
    return local_ip

def fetch_ip_page():
    window = Tk()
    window.geometry("602x590")
    window.configure(bg="#FFFFFF")
    window.title("Fetch IP")

    canvas = Canvas(
        window,
        bg="#FFFFFF",
        height=590,
        width=602,
        bd=0,
        highlightthickness=0,
        relief="ridge"
    )
    canvas.place(x=0, y=0)

    output_label = Label(window, text="Output", font=("BalooBhai Regular", 14), bg="#FFFFFF")
    output_label.place(x=90, y=340)

    output_text = Text(window, wrap="word", height=12, width=60, bg="#D3D3D3")
    output_text.place(x=50, y=370)

    scrollbar = Scrollbar(window, command=output_text.yview)
    scrollbar.place(x=540, y=370, height=200)

    fetch_ip(output_text)

    window.resizable(False, False)
    window.mainloop()

def fetch_ip(output_text):
    local_ip = list(get_local_ip().split("."))
    local_ip.pop()
    local_ip.append("0/24")
    target_ip = '.'.join(local_ip)

    output_file = "fetch_ip_result.txt"

    with open(output_file, "w") as file:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, verbose=0)[0]
        clients = []

        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        file.write("Scan Date: " + datetime.now().strftime("%Y/%m/%d Time: %H:%M:%S") + "\n")
        file.write("Available devices in the network:\n")
        file.write("IP" + " " * 18 + "MAC\n")

        for client in clients:
            file.write("{:16}    {}\n".format(client['ip'], client['mac']))

        time.sleep(1)

    output_text.delete(1.0, "end")

    with open(output_file, 'r') as result_file:
        result_content = result_file.read()
        output_text.insert("end", result_content)

    output_text.insert("end", f"\nFetch IP results saved to {output_file}\n")

if __name__ == "__main__":
    fetch_ip_page()
