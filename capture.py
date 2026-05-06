from scapy.all import sniff, wrpcap
import threading
import requests

def generate_traffic(url):
    try:
        requests.get(url, timeout=10, verify=False)
    except:
        pass

def capture_traffic(url, output_file="capture.pcap", duration=10):
    packets = []

    def packet_callback(packet):
        packets.append(packet)

    traffic_thread = threading.Thread(target=generate_traffic, args=(url,))
    traffic_thread.start()

    sniff(timeout=duration, prn=packet_callback)

    wrpcap(output_file, packets)
    return output_file