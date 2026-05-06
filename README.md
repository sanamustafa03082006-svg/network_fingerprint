# 🌐 NetPrint — Network Fingerprint Analyzer

A web-based tool that captures live network traffic when a user visits a website, analyzes the captured packets, and produces a unique **network fingerprint** — a compact behavioral profile summarizing how the site communicates.

Built as an educational aid for networking students to visually observe real-world differences in network behavior.

---

## 📸 Preview

> Enter a URL → Capture live traffic → View fingerprint + charts

---

## ✨ Features

- 🔍 **Live Packet Capture** — Uses Scapy to sniff real network traffic
- 📊 **Protocol Distribution** — Pie chart showing TCP, UDP, DNS, ICMP breakdown
- 📦 **Packet Size Histogram** — Bar chart grouping packets by size range
- 📈 **Traffic Timeline** — Line chart of bytes transferred per second
- 🏷️ **Behavior Classification** — Labels sites as Streaming, Social Media, Static Content, or API-Heavy
- 🆚 **Side-by-Side Comparison** — Compare two websites with color-coded diff indicators

---

## 🛠️ Tech Stack

| Technology | Role |
|------------|------|
| Python 3.x | Backend logic and data processing |
| Scapy | Low-level packet capture and parsing |
| Flask | REST API server |
| HTML / CSS | Frontend structure and styling |
| JavaScript | API calls and chart rendering |
| Chart.js | Protocol pie, size histogram, timeline charts |

---

## 📁 Project Structure

```
network_fingerprint/
│
├── app.py              # Flask server and API routes
├── capture.py          # Scapy packet capture
├── extract.py          # Feature extraction from .pcap
├── fingerprint.py      # Fingerprint JSON assembly
├── classify.py         # Rule-based behavior classifier
│
├── templates/
│   └── index.html      # Frontend UI
│
├── static/
│   └── script.js       # Chart.js rendering and API calls
│
└── capture.pcap        # Temporary packet capture file
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/network_fingerprint.git
cd network_fingerprint
```

### 2. Install dependencies
```bash
pip install flask scapy requests
```

### 3. Run as Administrator
> ⚠️ Scapy requires administrator/root privileges to capture packets.

**Windows** — Right-click VS Code or terminal → **Run as Administrator**, then:
```bash
python app.py
```

**Linux/Mac:**
```bash
sudo python app.py
```

### 4. Open in browser
```
http://127.0.0.1:5000
```

---

## 🚀 How to Use

### Single URL Analysis
1. Enter a URL (e.g. `https://example.com`)
2. Click **▶ Analyze Network Traffic**
3. Wait ~10 seconds for capture to complete
4. View the fingerprint card, protocol chart, histogram, and timeline

### Compare Two Websites
1. Click **Compare Two URLs** toggle
2. Enter two URLs
3. Click Analyze — takes ~20 seconds (two captures)
4. View side-by-side comparison with ▲/▼ diff indicators

---

## 📤 API Endpoints

### `POST /api/analyze`
Captures and analyzes a single URL.

**Request:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "site_url": "https://example.com",
  "capture_timestamp": "2026-01-05 16:01:00",
  "total_packets": 62,
  "total_bytes": 21700,
  "mean_packet_size": 350.31,
  "max_packet_size": 2958,
  "top_protocol": "UDP",
  "unique_ips": ["93.184.216.34"],
  "dns_queries": ["example.com."],
  "behavior_label": "Static Content",
  "confidence": 80,
  "protocol_distribution": { "TCP": 30.0, "UDP": 50.0, "DNS": 15.0, "ICMP": 5.0 },
  "buckets": { "0-100": 31, "101-500": 10, "501-1000": 11, "1001+": 10 },
  "timeline": { "1735": 4200, "1736": 8900 }
}
```

### `POST /api/compare`
Captures and compares two URLs.

**Request:**
```json
{ "url1": "https://example.com", "url2": "https://google.com" }
```

**Response:**
```json
{
  "fingerprint1": { ... },
  "fingerprint2": { ... }
}
```

---

## 📊 Behavior Classification Rules

| Label | Conditions |
|-------|-----------|
| Streaming | Total bytes > 500KB AND mean packet size > 1000B |
| Social Media | Unique IPs > 10 AND total packets > 200 |
| Static Content | Total packets < 150 AND total bytes < 100KB |
| API-Heavy | Top protocol is TCP AND mean packet size < 500B |
| Unknown | Does not match any pattern |

---

## ⚠️ Notes

- Run with **administrator privileges** on Windows for Scapy to work
- Capture window is **10 seconds** by default
- Background network activity may appear in captures (WhatsApp, Google services, etc.)
- For academic/educational use only

---

## 👩‍💻 Author

**Sana Faisal**  
Network Fingerprint Analyzer — Networking Course Project
