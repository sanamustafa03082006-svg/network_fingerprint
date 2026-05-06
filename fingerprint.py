from classify import classify
from datetime import datetime

def generate_fingerprint(features, url):
    label, confidence = classify(features)

    return {
        "site_url": url,
        "capture_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_packets": features["total_packets"],
        "total_bytes": features["total_bytes"],
        "mean_packet_size": features["mean_packet_size"],
        "max_packet_size": features["max_packet_size"],
        "top_protocol": max(features["protocol_distribution"], key=features["protocol_distribution"].get),
        "protocol_distribution": features["protocol_distribution"],
        "unique_ips": features["unique_ips"],
        "dns_queries": features["dns_queries"],
        "behavior_label": label,
        "confidence": confidence,
        "buckets": features["buckets"],
        "timeline": features["timeline"]
    }