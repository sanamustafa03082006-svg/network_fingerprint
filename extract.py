from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP
import statistics

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)

    packet_sizes = []
    unique_ips = set()
    dns_queries = []
    total_bytes = 0
    protocols = {"TCP": 0, "UDP": 0, "DNS": 0, "ICMP": 0, "Other": 0}
    arrival_times = []

    for pkt in packets:
        size = len(pkt)
        packet_sizes.append(size)
        total_bytes += size
        arrival_times.append(float(pkt.time))

        if pkt.haslayer(IP):
            unique_ips.add(pkt[IP].dst)

        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocols["ICMP"] += 1
        else:
            protocols["Other"] += 1

        if pkt.haslayer(DNS) and pkt[DNS].qd:
            protocols["DNS"] += 1
            try:
                dns_queries.append(pkt[DNS].qd.qname.decode())
            except:
                pass

    total = len(packets) or 1
    protocol_distribution = {k: round(v / total * 100, 2) for k, v in protocols.items()}

    # Packet size buckets
    buckets = {"0-100": 0, "101-500": 0, "501-1000": 0, "1001+": 0}
    for size in packet_sizes:
        if size <= 100:
            buckets["0-100"] += 1
        elif size <= 500:
            buckets["101-500"] += 1
        elif size <= 1000:
            buckets["501-1000"] += 1
        else:
            buckets["1001+"] += 1

    # Timeline: bytes per second
    timeline = {}
    for pkt in packets:
        sec = int(float(pkt.time))
        timeline[sec] = timeline.get(sec, 0) + len(pkt)
    timeline = dict(sorted(timeline.items()))

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "mean_packet_size": round(statistics.mean(packet_sizes), 2) if packet_sizes else 0,
        "max_packet_size": max(packet_sizes) if packet_sizes else 0,
        "min_packet_size": min(packet_sizes) if packet_sizes else 0,
        "protocol_distribution": protocol_distribution,
        "unique_ips": list(unique_ips),
        "dns_queries": dns_queries,
        "buckets": buckets,
        "timeline": timeline
    }