# Packet Analyzer — Web UI

A browser-based dashboard for the DPI (Deep Packet Inspection) engine.

---

## Requirements

- Python 3.8+
- pip

---

## Setup & Run

### Windows (quickest)

Double-click `run.bat` — it installs Flask automatically and opens the browser.

### Manual

```bash
# 1. Install dependency
pip install -r requirements.txt

# 2. Start the server
python server.py

# 3. Open in browser
http://127.0.0.1:5000
```

---

## Usage

1. Open `http://127.0.0.1:5000`
2. Go to **Upload PCAP** in the sidebar
3. Drag and drop any `.pcap` file (a sample `test_dpi.pcap` is included)
4. The dashboard auto-populates with:
   - Packet & byte counts, forwarded vs blocked
   - App distribution chart (YouTube, Netflix, TikTok, etc.)
   - Protocol breakdown
   - Packet timeline
   - Top source/destination IPs
5. Use **Packets** to browse and filter individual packets
6. Use **Connections** to view per-flow statistics
7. Use **Blocking Rules** to block IPs, domains, ports, or apps — click **Apply Rules** to re-analyze

---

## Project Structure

```
Packet_analyzer-main/
├── server.py          # Flask API + Python PCAP parser
├── templates/
│   └── index.html     # Web dashboard (single page)
├── requirements.txt   # Flask only
├── run.bat            # Windows one-click launcher
├── test_dpi.pcap      # Sample PCAP for testing
└── src/ include/      # C++ DPI engine source
```

---

## Stopping the Server

Press `Ctrl+C` in the terminal.
