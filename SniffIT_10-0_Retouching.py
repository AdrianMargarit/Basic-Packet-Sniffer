##########################################
############# Requirements ###############
# pip install argparse
# pip install argparse-utils
# pip install python-csv
# pip install queuelib
# pip install regex
# pip install sockets
# pip install socket.py
# pip install os-sys
# pip install multithreading
# pip install threading2
# pip install threaded
# pip install python-time
# pip install scapy
##########################################

import argparse
import csv
import queue
import re
import socket
import sys
import threading
import time
import atexit

import scapy.all as scapy
from scapy.all import *
from scapy.layers import http

class NetworkAnalyzerCLI:
    
    def __init__(self, interface, flag_p, flag_u, flag_v):
        # Register save_packet_data as an exit handler
        atexit.register(self.save_packet_data)

        self.sniff_thread = None
        self.packet_queue = queue.Queue()
        self.interface = interface
        self.selected_flag = None
        
        if flag_p:
            self.selected_flag = "p"
        elif flag_u:
            self.selected_flag = "u"
        elif flag_v:
            self.selected_flag = "v"    


    def start_sniffing(self):
        try:
            # Only start a new sniffing thread if one is not already running
            if self.sniff_thread is None:
                # Start sniffing thread
                self.sniff_thread = threading.Thread(target=self.sniff_packets)
                
                # Set as daemon thread
                self.sniff_thread.setDaemon(True)
                
                self.sniff_thread.start()

        except Exception as e:
            print(e)


    def stop_sniffing(self):
        try:
            # Stop sniffing thread
            if self.sniff_thread:
                self.sniff_thread.join()
                self.sniff_thread = None

        except Exception as e:
            print(e)


    def save_packet_data(self):
        try:
            current_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
            file_name = f"Sniffed-{current_time}.txt"

            with open(file_name, "w") as f:
                while not self.packet_queue.empty():
                    packet_data = self.packet_queue.get()
                    f.write(repr(packet_data) + "\n")

            print(f"Packet data saved to {file_name}")

        except Exception as e:
            print(e)

    def sniff_packets(self):
        # Sniff packets and add them to the packet queue
        try:
            print("Starting packet sniffing...")
            while True:
                packet = sniff(iface=self.interface, count=1, prn=self.process_sniffed_packet)[0]
                packet_data = self.get_packet_details(packet)

                if packet_data:
                    # self.packet_queue.put(packet_data)
                    # Print packet details using the desired format
                    print(f"[+] Source IP: {packet_data['src_ip']}")
                    print(f"        [+] Source Port: {packet_data['src_port']}")
                    print(f"\n[+] Destination IP: {packet_data['dst_ip']}")
                    print(f"        [+] Destination Port: {packet_data['dst_port']}")
                    print(f"\n[+] Timestamp: {packet_data['timestamp']}\n")

                if self.selected_flag == "p":
                    print(f"{packet_data['src_ip']}:{packet_data['src_port']} --> {packet_data['dst_ip']}:{packet_data['dst_port']}")
                elif self.selected_flag == "u":
                    if packet_data["username"] or packet_data["password"]:
                        print(f"Username: {packet_data['username']}, Password: {packet_data['password']}")
                # elif self.selected_flag == "v":
                    # print(packet_data)
                elif self.selected_flag == "h":
                    print("The program has the following flags:")
                    print("-p or --P: Output source IP, source port, destination IP, and destination port")
                    print("-u or --U: Output only username and password")
                    print("-v or --V: Output everything (source IP, source port, destination IP, destination port, username, password, protocol, total length, time, hex string, char string) in a verbose mode")
                    print("-h or --help: Display help menu for how to use the program with its flags and what they are doing")

                # Add a delay to avoid spamming packet details
                time.sleep(10)

        except KeyboardInterrupt:
            print("KeyboardInterrupt detected. Stopping packet sniffing...")
            sys.exit()


    def get_url(self, packet):
        try:
            # Check if the packet contains HTTP data
            if packet[TCP].dport == 80:
                # Parse the raw HTTP data to get the URL
                http_data = packet[TCP].payload
                http_headers = str(http_data).split("\r\n")

                for header in http_headers:
                    if "GET" in header or "POST" in header:
                        url = header.split(" ")[1]
                        return url

        except IndexError:
            # Ignore packets that do not contain HTTP data
            pass

        return ""


    def get_login_info(self, packet):
        # Check if the packet contains a login form
        if packet.haslayer(Raw):
            keywords = ["username", "user", "login", "password", "pass"]
            packet_data = repr(packet[Raw].load)

            for keyword in keywords:
                if keyword in packet_data.lower():
                    return packet_data

        return ""


    def process_sniffed_packet(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet)
            print(f"\n\n[+] HTTP Request >> {str(url)}")

            login_info = self.get_login_info(packet)
            if login_info:
                print("\n[+][+][+] Possible username and password found! [+][+][+]\n")
                credentials = login_info.split("&")
                for credential in credentials:
                    key, value = credential.split("=")
                    print(f"*********[+][+][+] {key.capitalize()}: {value} [+][+][+]*********")


    def get_packet_details(self, packet):
        # Extracts relevant details from a packet and returns them in a dictionary
        packet_data = {}
        try:
            # Extract source and destination IP addresses and ports
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['src_port'] = packet[TCP].sport
            packet_data['dst_port'] = packet[TCP].dport

            # Extract HTTP headers and data (if present)
            if packet.haslayer(http.HTTPRequest):
                packet_data['protocol'] = 'HTTP'
                headers = packet[http.HTTPRequest].fields
                packet_data['headers'] = {k: headers[k] for k in headers if k != 'load'}
                if packet.haslayer(http.HTTPResponse):
                    packet_data['data'] = packet[http.HTTPResponse].load

            # Extract login credentials (if present)
            login_info = self.get_login_info(packet)
            if login_info:
                packet_data['username'] = login_info['username']
                packet_data['password'] = login_info['password']

            # Extract timestamp and packet data (in hex and char format)
            packet_data['timestamp'] = str(datetime.now())
            
            # Add hex string, char string, and protocol when flag_v is True
            if self.selected_flag == "v":
                packet_data['hex'] = packet.hexdump()
                packet_data['char'] = packet.payload.decode(errors='ignore')
                packet_data['protocol'] = packet[TCP].flags
                return packet_data
        
            packet_data['hex'] = None
            packet_data['char'] = None
            packet_data['protocol'] = None

        except Exception as e:
            print(e)

        return packet_data


    def start(self):
        try:
            # Start the sniffing thread
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

            # Start the packet processing loop
            self.process_packet_loop()
        except KeyboardInterrupt:
            print("KeyboardInterrupt detected. Stopping packet sniffing...")
            self.stop_sniffing()
            self.process_packet_queue()
            self.save_packet_data()
            print("[+] Program exited successfully.")

    
    def stop(self):
        # Process remaining packets in the queue
        self.process_packet_queue()

        # Stop sniffing packets
        self.sniff_thread.stop()

        print("[+] Program exited successfully.")


    def process_packet_queue(self):
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.process_sniffed_packet(packet)


    def process_packet_loop(self):
        # Continuously process packets as they arrive
        sniff(prn=self.process_sniffed_packet, iface=self.interface)


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument("interface", help="Interface to sniff packets on")
    parser.add_argument("-p", "--P", help="Search for IPs and ports", dest="flag_p", action="store_true")
    parser.add_argument("-u", "--U", help="Search for username and password", dest="flag_u", action="store_true")
    parser.add_argument("-v", "--V", help="Verbose mode", dest="flag_v", action="store_true")
    args = parser.parse_args()

    # Start the sniffer
    sniffer = NetworkAnalyzerCLI(args.interface, args.flag_p, args.flag_u, args.flag_v)
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        sniffer.stop()