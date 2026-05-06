from flask import Flask, request, jsonify, render_template
from capture import capture_traffic
from extract import extract_features
from fingerprint import generate_fingerprint

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    pcap_file = capture_traffic(url)
    features = extract_features(pcap_file)
    fingerprint = generate_fingerprint(features, url)

    return jsonify(fingerprint)

@app.route("/api/compare", methods=["POST"])
def compare():
    data = request.get_json()
    url1 = data.get("url1")
    url2 = data.get("url2")

    pcap1 = capture_traffic(url1, "capture1.pcap")
    features1 = extract_features(pcap1)
    fp1 = generate_fingerprint(features1, url1)

    pcap2 = capture_traffic(url2, "capture2.pcap")
    features2 = extract_features(pcap2)
    fp2 = generate_fingerprint(features2, url2)

    return jsonify({"fingerprint1": fp1, "fingerprint2": fp2})

if __name__ == "__main__":
    app.run(debug=True)