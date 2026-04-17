# """this script captures network packets and prints the source and destination.IP addresses of each packet.
# It uses the scapy library to sniff packets and process them. 
#The script will capture 10 packets and then stop."""
from scapy.all import sniff
from scapy.layers.inet import IP
#global counter 
counter = 0
def handle_packet(packet):
    global counter
    #if packet has IP layer
    if packet.haslayer(IP):
        #extract src and dst IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        counter += 1
        print(f"Packet {counter}: {src_ip} -> {dst_ip}")
    else:
        #do nothing
        pass

if __name__ == "__main__":
    print("Starting packet capture...")
    sniff(count=10, prn=handle_packet, store=False)
    print("Packet capture complete.")

