"""
This script captures network packets and prints the source and destination.IP addresses of each packet.
It uses the scapy library to sniff packets and process them. 
The script will capture 10 packets and then stop.
"""
from scapy.all import sniff, Raw
from scapy.layers.inet import IP,UDP

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
        payload_bytes = b""
        payload_text = ""
        payload_length = 0
        l7_type = "UNKNOWN"
        if packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                l7_type = "DNS"
            else:
                pass
        if packet.haslayer(Raw):
            payload_bytes= packet[Raw].load
            payload_length= len(payload_bytes)
            payload_text= payload_bytes.decode(errors="ignore")
            #checking for http payload
            if payload_text.startswith("GET ") or payload_text.startswith("POST ") or payload_text.startswith("HTTP/"):
                l7_type = "HTTP"
        else:
            pass
        
        #output format [PACKET 6] 192.168.1.2 -> 34.223.124.45 | L7=HTTP | payload_len=76
        print(f"[PACKET {counter}] {src_ip} -> {dst_ip} | L7={l7_type} | payload_len={payload_length}")
    else:
        #do nothing
        pass
    

if __name__ == "__main__":
    print("Starting packet capture...")
    sniff(count=10, prn=handle_packet, store=False)
    print("Packet capture complete.")

