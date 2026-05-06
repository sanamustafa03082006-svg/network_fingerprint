def classify(features):
    total_bytes = features["total_bytes"]
    mean_size = features["mean_packet_size"]
    total_packets = features["total_packets"]
    unique_ips = len(features["unique_ips"])
    top_protocol = max(features["protocol_distribution"], key=features["protocol_distribution"].get)

    if total_bytes > 500000 and mean_size > 1000:
        return "Streaming", 90
    elif unique_ips > 10 and total_packets > 200:
        return "Social Media", 85
    elif total_packets < 150 and total_bytes < 100000:
        return "Static Content", 80
    elif top_protocol == "TCP" and mean_size < 500:
        return "API-Heavy", 75
    else:
        return "Unknown", 60