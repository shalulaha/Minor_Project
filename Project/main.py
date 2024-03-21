from pathlib import Path
from tkinter import Tk, Canvas, Text, Scrollbar, Label, Button
import scapy.all as scapy
from scapy.all import ARP, Ether, srp
import socket
import nmap
import json
import time
from datetime import datetime

OUTPUT_PATH = Path(__file__).parent

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception as e:
        local_ip = "Unable to determine local IP"
    return local_ip

def discover_hosts(target_subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_subnet, arguments='-sn')
    return nm.all_hosts()

def discover_open_ports(target_host):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_host, arguments='-F')
    if target_host in nm.all_hosts() and 'tcp' in nm[target_host]:
        return nm[target_host]['tcp']
    else:
        return {}

def save_scan_results_to_file(filename, scan_results):
    with open(filename, 'w') as file:
        json.dump(scan_results, file, indent=4)

def read_and_save_scan_results(input_file, output_file):
    with open(input_file, 'r') as file:
        scan_results = json.load(file)

    with open(output_file, 'w') as file:
        file.write("Scan Date: " + datetime.now().strftime("%Y/%m/%d Time: %H:%M:%S") + "\n")
        for ip_address, ports in scan_results.items():
            file.write(f"IP Address: {ip_address}\n")
            for port, port_info in ports.items():
                line = (
                    f"  Port: {port}, State: {port_info['state']}, "
                    f"Name: {port_info['name']}, Conf: {port_info['conf']}, CPE: {port_info['cpe']}\n"
                )
                file.write(line)
            file.write("\n")  # Add a newline after each IP entry
            
            
def read_and_save_scan_results_single(input_file, output_file):
    with open(input_file, 'r') as file:
        scan_results = json.load(file)

    with open(output_file, 'a') as file:
        file.write("Scan Date: " + datetime.now().strftime("%Y/%m/%d Time: %H:%M:%S") + "\n")
        for ip_address, ports in scan_results.items():
            file.write(f"IP Address: {ip_address}\n")
            for port, port_info in ports.items():
                line = (
                    f"  Port: {port}, State: {port_info['state']}, "
                    f"Name: {port_info['name']}, Conf: {port_info['conf']}, CPE: {port_info['cpe']}\n"
                )
                file.write(line)
            file.write("\n")  # Add a newline after each IP entry

def fetch_ip():
    
    # Display the contents in the output window
    output_text.delete(1.0, "end")
    
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

    # Display the contents in the output window
    output_text.delete(1.0, "end")
    
    with open(output_file, 'r') as result_file:
        result_content = result_file.read()
        output_text.insert("end", result_content)

    output_text.insert("end", f"\nFetch IP results saved to {output_file}\n")



def port_scanner():
    local_ip = list(get_local_ip().split("."))
    local_ip.pop()
    local_ip.append("0/24")
    target_ip = '.'.join(local_ip)

    live_hosts = discover_hosts(target_ip)

    scan_results = {}

    for host in live_hosts:
        open_ports = discover_open_ports(host)
        scan_results[host] = open_ports

    output_file = "port_scan_result.json"
    save_scan_results_to_file(output_file, scan_results)
    
    input_file = output_file
    timestamp = datetime.now().strftime("Date: %Y/%m/%d Time: %H:%M:%S")
    output_file_formatted = f"formatted_scan_results.txt"
    read_and_save_scan_results(input_file, output_file_formatted)
    read_and_save_scan_results_single(input_file, "All_PortScann_Result.txt")
    
    # Clear the existing content in the Text widget
    output_text.delete(1.0, "end")

    # Read the content of the formatted file and insert it into the Text widget
    with open(output_file_formatted, 'r') as formatted_file:
        formatted_content = formatted_file.read()
        output_text.insert("end", formatted_content)

    output_text.insert("end", f"\nScan results saved to {output_file_formatted}\n")


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
    # local_ip.append("0/24")
    target_ip = '.'.join(local_ip)
    return target_ip

def get_data_usage_for_3():
    data_usage = {}
    
    end_time = time.time() + 10
    while time.time() < end_time:
        packets = scapy.sniff(filter="ip", count=10)

        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                data_size = len(packet)
                
                data_usage[src_ip] = data_usage.get(src_ip, 0) + data_size
                data_usage[dst_ip] = data_usage.get(dst_ip, 0) + data_size

    data_usage_in_mb = {ip: usage / (1024) for ip, usage in data_usage.items()}
    return data_usage_in_mb

def save_data_usage_to_file_for_3(data_usage, filename="data_usage.txt"):
    timestamp = datetime.now().strftime("Date: %Y/%m/%d Time: %H:%M:%S")
    ip_range=port_scanner_for_3()
    with open(filename, 'w') as file:
        file.write(f"Scanning Starting : {timestamp}\n")
        for ip, usage in data_usage.items():
            if ip_range in ip:
                file.write(f"Device with IP {ip} used {usage:.2f} MB in the last 5 minutes.\n")


def bandwidth_rate():
    
    # Display the contents in the output window
    output_text.delete(1.0, "end")
    
    output_text.insert("end", "BANDWIDTH RATE button clicked\n")
    data_usage = get_data_usage_for_3()
    
    filename="data_usage.txt"
    save_data_usage_to_file_for_3(data_usage,filename)
    
    with open(filename, 'r') as result_file:
        result_content = result_file.read()
        output_text.insert("end", result_content)
        
    output_text.insert("end","\nData usage details saved to data_usage.txt.")

window = Tk()
window.geometry("602x590")
window.configure(bg="#FFFFFF")
window.title("Admin")  # Change the window title to "Admin"

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
canvas.create_rectangle(
    0.0,
    0.0,
    598.0,
    47.0,
    fill="#CAE8E5",
    outline=""
)
canvas.create_text(
    170.0,
    12.0,
    anchor="nw",
    text="NETWORK ADMINISTRATOR",
    fill="#000000",
    font=("IrishGrover Regular", 20 * -1)
)

fetch_ip_button = Button(
    window,
    text="FETCH IP",
    command=fetch_ip,
    font=("BalooBhai Regular", 14),
    bg="#53898D",
    fg="#FFFFFF",
)
fetch_ip_button.place(x=200, y=120, width=180, height=40)

port_scanner_button = Button(
    window,
    text="PORT SCANNER",
    command=port_scanner,
    font=("BalooBhai Regular", 14),
    bg="#53898D",
    fg="#FFFFFF",
)
port_scanner_button.place(x=200, y=200, width=180, height=40)

bandwidth_rate_button = Button(
    window,
    text="BANDWIDTH RATE",
    command=bandwidth_rate,
    font=("BalooBhai Regular", 14),
    bg="#53898D",
    fg="#FFFFFF",
)
bandwidth_rate_button.place(x=200, y=290, width=180, height=40)

# Label for the output window
output_label = Label(window, text="Output", font=("BalooBhai Regular", 14), bg="#FFFFFF")
output_label.place(x=90, y=340)

# Add an output window (Text widget) at the bottom
output_text = Text(window, wrap="word", height=12, width=60, bg="#D3D3D3")
output_text.place(x=50, y=370)

# Add a scrollbar to the output window
scrollbar = Scrollbar(window, command=output_text.yview)
scrollbar.place(x=540, y=370, height=200)  # Adjust the height to match the output window


window.resizable(False, False)
window.mainloop()









# import scapy.all as scapy
# import time
# import socket
# from datetime import datetime

# def get_local_ip_for_3():
#     try:
#         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         s.settimeout(0.1)
#         s.connect(("8.8.8.8", 80))
#         local_ip = s.getsockname()[0]
#     except Exception as e:
#         local_ip = "Unable to determine local IP"
#     return local_ip

# def port_scanner_for_3():
#     local_ip = list(get_local_ip_for_3().split("."))
#     local_ip.pop()
#     local_ip.pop()
#     # local_ip.append("0/24")
#     target_ip = '.'.join(local_ip)
#     return target_ip

# def get_data_usage_for_3():
#     data_usage = {}
    
#     end_time = time.time() + 30
#     while time.time() < end_time:
#         packets = scapy.sniff(filter="ip", count=10)

#         for packet in packets:
#             if packet.haslayer(scapy.IP):
#                 src_ip = packet[scapy.IP].src
#                 dst_ip = packet[scapy.IP].dst
#                 data_size = len(packet)
                
#                 data_usage[src_ip] = data_usage.get(src_ip, 0) + data_size
#                 data_usage[dst_ip] = data_usage.get(dst_ip, 0) + data_size

#     data_usage_in_mb = {ip: usage / (1024) for ip, usage in data_usage.items()}
#     return data_usage_in_mb

# def save_data_usage_to_file_for_3(data_usage, filename="data_usage.txt"):
#     timestamp = datetime.now().strftime("Date: %Y/%m/%d Time: %H:%M:%S")
#     ip_range=port_scanner_for_3()
#     with open(filename, 'a') as file:
#         file.write(f"Scanning Starting : {timestamp}\n")
#         for ip, usage in data_usage.items():
#             if ip_range in ip:
#                 file.write(f"Device with IP {ip} used {usage:.2f} MB in the last 5 minutes.\n")

# if __name__ == "__main__":
#     data_usage = get_data_usage_for_3()
    
#     save_data_usage_to_file_for_3(data_usage)
#     print("Data usage details saved to data_usage.txt.")