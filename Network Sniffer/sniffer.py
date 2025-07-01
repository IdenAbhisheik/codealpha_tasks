import csv                         
from scapy.all import sniff, IP, TCP, UDP 
csv_file = open("captured_packets.csv", mode="w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port"])
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]      
        src_ip = ip_layer.src      
        dst_ip = ip_layer.dst     
        proto = ip_layer.proto     
        src_port = ""
        dst_port = ""
        proto_name = ""

        # Check if it's TCP
        if TCP in packet:
            proto_name = "TCP"
            src_port = packet[TCP].sport     # Source port number
            dst_port = packet[TCP].dport     # Destination port number

        # Check if it's UDP
        elif UDP in packet:
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # If not TCP or UDP, just show protocol number
        else:
            proto_name = f"IP({proto})"

        # Print info on the screen
        print(f"\n[+] Packet Captured:")
        print(f"    From: {src_ip} To: {dst_ip}")
        print(f"    Protocol: {proto_name}")
        if src_port and dst_port:
            print(f"    Ports: {src_port} -> {dst_port}")

        # Write the packet info to the CSV file
        csv_writer.writerow([src_ip, dst_ip, proto_name, src_port, dst_port])

# Show message when starting
print("Sniffer started... Capturing 10 packets and saving to captured_packets.csv")

# Start sniffing: capture 10 packets from the IP layer
sniff(filter="ip", prn=packet_callback, count=10)

# Close the CSV file after sniffing is complete
csv_file.close()
print("Capture complete. Check 'captured_packets.csv' for saved data.")
