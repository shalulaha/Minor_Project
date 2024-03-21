from tkinter import Tk, Canvas, Text, Scrollbar, Label, Button
import nmap
import json
from datetime import datetime
from pathlib import Path

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

def port_scanner_page():
    window = Tk()
    window.geometry("602x590")
    window.configure(bg="#FFFFFF")
    window.title("Port Scanner")

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

    port_scanner(output_text)

    window.resizable(False, False)
    window.mainloop()

def port_scanner(output_text):
    local_ip = get_local_ip()
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

    output_text.delete(1.0, "end")

    with open(output_file_formatted, 'r') as formatted_file:
        formatted_content = formatted_file.read()
        output_text.insert("end", formatted_content)

    output_text.insert("end", f"\nScan results saved to {output_file_formatted}\n")

if __name__ == "__main__":
    port_scanner_page()
