from tkinter import Tk, Canvas, Text, Scrollbar, Label, Button
import scapy.all as scapy
import socket
import time
from datetime import datetime

def get_local_ip_for_3():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception as e:
        local_ip = "Unable to determine local IP"
    return local_ip

def port_scanner_for_3():
    local_ip = list(get_local_ip_for_3().split("."))
    local_ip.pop()
    local_ip.pop()
    target_ip = '.'.join(local_ip)
    return target_ip

def get_data_usage_for_3():
    data_usage = {}
    
    end_time = time.time() + 60
    while time.time() < end_time:
        packets = scapy.sniff(filter="ip", count=10)

        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                data_size = len(packet)
                
                data_usage[src_ip] = data_usage.get(src_ip, 0) + data_size
                data_usage[dst_ip] = data_usage.get(dst_ip, 0) + data_size

    data_usage_in_mb = {ip: (usage) / (1024) for ip, usage in data_usage.items()}
    return data_usage_in_mb

def save_data_usage_to_file_for_3(data_usage, filename="data_usage.txt"):
    timestamp = datetime.now().strftime("Date: %Y/%m/%d Time: %H:%M:%S")
    ip_range = port_scanner_for_3()
    with open(filename, 'w') as file:
        file.write(f"Scanning Starting : {timestamp}\n")
        for ip, usage in data_usage.items():
            if ip_range in ip:
                file.write(f"Device with IP {ip} used {usage:.2f} MB in the last 1 minutes.\n")

def bandwidth_rate_page():
    window = Tk()
    window.geometry("602x590")
    window.configure(bg="#FFFFFF")
    window.title("Bandwidth Rate")

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

    bandwidth_rate(output_text)

    window.resizable(False, False)
    window.mainloop()

def bandwidth_rate(output_text):
    output_text.delete(1.0, "end")

    output_text.insert("end", "BANDWIDTH RATE button clicked\n")
    data_usage = get_data_usage_for_3()

    filename = "data_usage.txt"
    save_data_usage_to_file_for_3(data_usage, filename)

    with open(filename, 'r') as result_file:
        result_content = result_file.read()
        output_text.insert("end", result_content)

    output_text.insert("end", "\nData usage details saved to data_usage.txt.")

if __name__ == "__main__":
    bandwidth_rate_page()
