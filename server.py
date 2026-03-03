"""
Packet Analyzer Web Server
Flask bridge between the C++ DPI engine and the web frontend.
"""

import os
import atexit
import struct
import socket
import subprocess
import json
import time
import threading
from pathlib import Path
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__, template_folder="templates", static_folder="static")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB (free tier friendly)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("static", exist_ok=True)

def cleanup_uploads():
    upload_file = Path(UPLOAD_FOLDER) / "upload.pcap"
    if upload_file.exists():
        upload_file.unlink()

atexit.register(cleanup_uploads)

# ─────────────────────────────────────────────
#  PCAP PARSER
# ─────────────────────────────────────────────

PCAP_GLOBAL_HEADER_FMT = "IHHiIII"  # 24 bytes
PCAP_PACKET_HEADER_FMT = "IIII"     # 16 bytes
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1

APP_DOMAINS = {
    "youtube": "YouTube",
    "googlevideo": "YouTube",
    "ytimg": "YouTube",
    "facebook": "Facebook",
    "fbcdn": "Facebook",
    "instagram": "Instagram",
    "netflix": "Netflix",
    "nflxvideo": "Netflix",
    "amazon": "Amazon",
    "amazonaws": "Amazon",
    "microsoft": "Microsoft",
    "office365": "Microsoft",
    "live.com": "Microsoft",
    "apple": "Apple",
    "icloud": "Apple",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "tiktok": "TikTok",
    "spotify": "Spotify",
    "zoom": "Zoom",
    "discord": "Discord",
    "github": "GitHub",
    "cloudflare": "Cloudflare",
    "twitter": "Twitter",
    "x.com": "Twitter",
    "google": "Google",
    "gmail": "Google",
}

PROTOCOL_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 50: "ESP", 51: "AH"}


def classify_domain(domain: str) -> str:
    domain_lower = domain.lower()
    for key, app in APP_DOMAINS.items():
        if key in domain_lower:
            return app
    return "Unknown"


def extract_tls_sni(payload: bytes):
    """Extract SNI from TLS Client Hello."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # TLS Handshake
            return None
        if payload[5] != 0x01:  # Client Hello
            return None
        idx = 43
        if idx >= len(payload):
            return None
        session_len = payload[idx]
        idx += 1 + session_len
        if idx + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[idx:idx+2])[0]
        idx += 2 + cs_len
        if idx >= len(payload):
            return None
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[idx:idx+2])[0]
        idx += 2
        end = idx + ext_total
        while idx + 4 <= end and idx + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[idx:idx+2])[0]
            ext_len  = struct.unpack("!H", payload[idx+2:idx+4])[0]
            idx += 4
            if ext_type == 0x0000:  # SNI
                if idx + 5 <= len(payload):
                    name_len = struct.unpack("!H", payload[idx+3:idx+5])[0]
                    sni = payload[idx+5:idx+5+name_len].decode("utf-8", errors="replace")
                    return sni
            idx += ext_len
    except Exception:
        pass
    return None


def extract_http_host(payload: bytes):
    """Extract HTTP Host header from plain HTTP."""
    try:
        text = payload[:4096].decode("utf-8", errors="replace")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line[5:].strip()
    except Exception:
        pass
    return None


def extract_dns_query(payload: bytes):
    """Extract DNS query name from a UDP DNS packet."""
    try:
        if len(payload) < 12:
            return None
        idx = 12
        labels = []
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:  # pointer
                break
            idx += 1
            labels.append(payload[idx:idx+length].decode("ascii", errors="replace"))
            idx += length
        return ".".join(labels) if labels else None
    except Exception:
        pass
    return None


def parse_pcap(filepath: str) -> dict:
    """Parse a PCAP file and return structured data."""
    packets = []
    connections = {}
    stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "other_packets": 0,
        "apps": defaultdict(int),
        "protocols": defaultdict(int),
        "top_sources": defaultdict(int),
        "top_destinations": defaultdict(int),
        "packet_sizes": [],
        "timeline": defaultdict(int),
    }

    try:
        with open(filepath, "rb") as f:
            header_data = f.read(24)
            if len(header_data) < 24:
                return {"error": "File too small to be a valid PCAP"}
            magic = struct.unpack("I", header_data[:4])[0]
            if magic == PCAP_MAGIC_BE:
                endian = ">"
            elif magic == PCAP_MAGIC_LE:
                endian = "<"
            else:
                return {"error": f"Invalid PCAP magic number: {hex(magic)}"}

            pkt_idx = 0
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_hdr)
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                timestamp = ts_sec + ts_usec / 1_000_000
                pkt_info = {
                    "id": pkt_idx,
                    "timestamp": timestamp,
                    "length": orig_len,
                    "proto": "Other",
                    "src_ip": "-",
                    "dst_ip": "-",
                    "src_port": "-",
                    "dst_port": "-",
                    "sni": None,
                    "app": "Unknown",
                    "action": "FORWARD",
                    "flags": [],
                }

                stats["total_packets"] += 1
                stats["total_bytes"] += orig_len
                stats["packet_sizes"].append(orig_len)
                minute_bucket = int(timestamp // 60) * 60
                stats["timeline"][str(minute_bucket)] += 1

                # Ethernet header (14 bytes)
                if len(raw) < 14:
                    packets.append(pkt_info)
                    pkt_idx += 1
                    continue

                ethertype = struct.unpack("!H", raw[12:14])[0]
                if ethertype != 0x0800:  # Only IPv4
                    pkt_info["proto"] = f"EtherType 0x{ethertype:04x}"
                    packets.append(pkt_info)
                    pkt_idx += 1
                    continue

                # IPv4 header
                if len(raw) < 34:
                    packets.append(pkt_info)
                    pkt_idx += 1
                    continue

                ip_start = 14
                ip_ihl = (raw[ip_start] & 0x0F) * 4
                ip_protocol = raw[ip_start + 9]
                src_ip = socket.inet_ntoa(raw[ip_start+12:ip_start+16])
                dst_ip = socket.inet_ntoa(raw[ip_start+16:ip_start+20])

                pkt_info["src_ip"] = src_ip
                pkt_info["dst_ip"] = dst_ip
                stats["top_sources"][src_ip] += 1
                stats["top_destinations"][dst_ip] += 1

                proto_name = PROTOCOL_NAMES.get(ip_protocol, f"IP/{ip_protocol}")
                pkt_info["proto"] = proto_name
                stats["protocols"][proto_name] += 1

                transport_start = ip_start + ip_ihl
                sni = None

                if ip_protocol == 6 and len(raw) >= transport_start + 20:  # TCP
                    stats["tcp_packets"] += 1
                    src_port = struct.unpack("!H", raw[transport_start:transport_start+2])[0]
                    dst_port = struct.unpack("!H", raw[transport_start+2:transport_start+4])[0]
                    data_offset = ((raw[transport_start+12] >> 4) & 0xF) * 4
                    tcp_flags_byte = raw[transport_start+13]
                    flags = []
                    if tcp_flags_byte & 0x02: flags.append("SYN")
                    if tcp_flags_byte & 0x10: flags.append("ACK")
                    if tcp_flags_byte & 0x01: flags.append("FIN")
                    if tcp_flags_byte & 0x04: flags.append("RST")
                    if tcp_flags_byte & 0x08: flags.append("PSH")

                    pkt_info["src_port"] = src_port
                    pkt_info["dst_port"] = dst_port
                    pkt_info["flags"] = flags
                    payload_start = transport_start + data_offset
                    payload = raw[payload_start:]

                    if dst_port == 443 or src_port == 443:
                        sni = extract_tls_sni(payload)
                    elif dst_port == 80 or src_port == 80:
                        sni = extract_http_host(payload)

                elif ip_protocol == 17 and len(raw) >= transport_start + 8:  # UDP
                    stats["udp_packets"] += 1
                    src_port = struct.unpack("!H", raw[transport_start:transport_start+2])[0]
                    dst_port = struct.unpack("!H", raw[transport_start+2:transport_start+4])[0]
                    pkt_info["src_port"] = src_port
                    pkt_info["dst_port"] = dst_port
                    payload = raw[transport_start+8:]
                    if dst_port == 53 or src_port == 53:
                        sni = extract_dns_query(payload)
                else:
                    stats["other_packets"] += 1

                if sni:
                    pkt_info["sni"] = sni
                    app = classify_domain(sni)
                    pkt_info["app"] = app
                    stats["apps"][app] += 1
                else:
                    stats["apps"]["Unknown"] += 1

                # Connection tracking
                if pkt_info["src_port"] != "-":
                    flow_key = (src_ip, dst_ip,
                                pkt_info["src_port"], pkt_info["dst_port"],
                                proto_name)
                    if flow_key not in connections:
                        connections[flow_key] = {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": pkt_info["src_port"],
                            "dst_port": pkt_info["dst_port"],
                            "protocol": proto_name,
                            "packets": 0,
                            "bytes": 0,
                            "sni": None,
                            "app": "Unknown",
                            "state": "NEW",
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                        }
                    conn = connections[flow_key]
                    conn["packets"] += 1
                    conn["bytes"] += orig_len
                    conn["last_seen"] = timestamp
                    if sni:
                        conn["sni"] = sni
                        conn["app"] = pkt_info["app"]
                    if "SYN" in pkt_info["flags"] and "ACK" not in pkt_info["flags"]:
                        conn["state"] = "SYN_SENT"
                    elif "SYN" in pkt_info["flags"] and "ACK" in pkt_info["flags"]:
                        conn["state"] = "ESTABLISHED"
                    elif conn["sni"]:
                        conn["state"] = "CLASSIFIED"

                if len(packets) < 1000:  # display first 1000 packets
                    packets.append(pkt_info)
                pkt_idx += 1

    except FileNotFoundError:
        return {"error": "Upload file not found"}
    except Exception as e:
        return {"error": str(e)}

    # finalize stats
    stats["apps"] = dict(stats["apps"])
    stats["protocols"] = dict(stats["protocols"])
    stats["top_sources"] = dict(
        sorted(stats["top_sources"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    stats["top_destinations"] = dict(
        sorted(stats["top_destinations"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    stats["timeline"] = dict(sorted(stats["timeline"].items()))
    avg_size = (sum(stats["packet_sizes"]) / len(stats["packet_sizes"])) if stats["packet_sizes"] else 0
    max_size = max(stats["packet_sizes"]) if stats["packet_sizes"] else 0
    stats.pop("packet_sizes")
    stats["avg_packet_size"] = round(avg_size, 1)
    stats["max_packet_size"] = max_size

    return {
        "packets": packets,
        "connections": list(connections.values()),
        "stats": stats,
    }


# ─────────────────────────────────────────────
#  IN-MEMORY STATE
# ─────────────────────────────────────────────

analysis_results: dict = {}
blocking_rules: dict = {
    "ips": [],
    "apps": [],
    "domains": [],
    "ports": [],
}
analysis_status: dict = {"state": "idle", "message": "", "progress": 0}


# ─────────────────────────────────────────────
#  BACKGROUND ANALYSIS WORKER
# ─────────────────────────────────────────────

def run_analysis(filepath: str):
    global analysis_results, analysis_status
    analysis_status = {"state": "running", "message": "Parsing PCAP file…", "progress": 10}
    try:
        result = parse_pcap(filepath)
        if "error" in result:
            analysis_status = {"state": "error", "message": result["error"], "progress": 0}
            return

        analysis_status["progress"] = 60
        analysis_status["message"] = "Applying blocking rules…"
        time.sleep(0.1)

        # Apply blocking rules to connections
        blocked_ips   = set(blocking_rules["ips"])
        blocked_apps  = set(blocking_rules["apps"])
        blocked_domains = blocking_rules["domains"]
        blocked_ports = set(int(p) for p in blocking_rules["ports"] if str(p).isdigit())

        blocked_count = 0
        for conn in result["connections"]:
            drop = False
            if conn["src_ip"] in blocked_ips or conn["dst_ip"] in blocked_ips:
                drop = True
            if conn["app"] in blocked_apps:
                drop = True
            if conn["sni"] and any(d.lower() in conn["sni"].lower() for d in blocked_domains):
                drop = True
            if conn["dst_port"] in blocked_ports or conn["src_port"] in blocked_ports:
                drop = True
            conn["blocked"] = drop
            if drop:
                blocked_count += 1

        for pkt in result["packets"]:
            drop = False
            if pkt["src_ip"] in blocked_ips or pkt["dst_ip"] in blocked_ips:
                drop = True
            if pkt["app"] in blocked_apps:
                drop = True
            if pkt["sni"] and any(d.lower() in pkt["sni"].lower() for d in blocked_domains):
                drop = True
            port_val = pkt.get("dst_port")
            if isinstance(port_val, int) and port_val in blocked_ports:
                drop = True
            pkt["action"] = "DROP" if drop else "FORWARD"

        result["stats"]["blocked_packets"] = blocked_count
        result["stats"]["forwarded_packets"] = result["stats"]["total_packets"] - blocked_count

        # Try running C++ binary if compiled
        cpp_binary = None
        for candidate in ["./dpi_engine", "./dpi_simple", "./packet_analyzer",
                          "dpi_engine.exe", "dpi_simple.exe"]:
            if Path(candidate).exists():
                cpp_binary = candidate
                break

        result["cpp_used"] = cpp_binary is not None

        analysis_status["progress"] = 90
        analysis_status["message"] = "Finalizing…"
        time.sleep(0.1)
        analysis_results = result
        analysis_status = {
            "state": "done",
            "message": f"Analysis complete — {result['stats']['total_packets']:,} packets processed",
            "progress": 100,
        }
    except Exception as e:
        analysis_status = {"state": "error", "message": str(e), "progress": 0}


# ─────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = "upload.pcap"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    thread = threading.Thread(target=run_analysis, args=(filepath,), daemon=True)
    thread.start()
    return jsonify({"message": "Upload successful, analysis started", "filename": file.filename})


@app.route("/api/status")
def status():
    return jsonify(analysis_status)


@app.route("/api/stats")
def stats():
    if not analysis_results:
        return jsonify({"error": "No analysis results yet"}), 404
    return jsonify(analysis_results.get("stats", {}))


@app.route("/api/packets")
def packets():
    if not analysis_results:
        return jsonify({"error": "No analysis results yet"}), 404
    page  = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 100))
    proto = request.args.get("proto", "")
    app_filter = request.args.get("app", "")
    action_filter = request.args.get("action", "")
    search = request.args.get("search", "").lower()

    pkts = analysis_results.get("packets", [])

    if proto:
        pkts = [p for p in pkts if p.get("proto", "").upper() == proto.upper()]
    if app_filter:
        pkts = [p for p in pkts if p.get("app", "").lower() == app_filter.lower()]
    if action_filter:
        pkts = [p for p in pkts if p.get("action", "").upper() == action_filter.upper()]
    if search:
        pkts = [p for p in pkts if
                search in str(p.get("src_ip","")).lower() or
                search in str(p.get("dst_ip","")).lower() or
                search in str(p.get("sni") or "").lower()]

    total = len(pkts)
    start = (page - 1) * limit
    return jsonify({"total": total, "page": page, "limit": limit, "packets": pkts[start:start+limit]})


@app.route("/api/connections")
def connections():
    if not analysis_results:
        return jsonify({"error": "No analysis results yet"}), 404
    conns = analysis_results.get("connections", [])
    sort_by = request.args.get("sort", "bytes")
    conns_sorted = sorted(conns, key=lambda c: c.get(sort_by, 0), reverse=True)
    return jsonify({"total": len(conns_sorted), "connections": conns_sorted[:500]})


@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify(blocking_rules)


@app.route("/api/rules", methods=["POST"])
def set_rules():
    global blocking_rules
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400
    blocking_rules = {
        "ips":     data.get("ips", []),
        "apps":    data.get("apps", []),
        "domains": data.get("domains", []),
        "ports":   data.get("ports", []),
    }
    # Re-run analysis if we have a cached upload
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], "upload.pcap")
    if Path(filepath).exists():
        thread = threading.Thread(target=run_analysis, args=(filepath,), daemon=True)
        thread.start()
    return jsonify({"message": "Rules updated", "rules": blocking_rules})


@app.route("/api/rules/reset", methods=["POST"])
def reset_rules():
    global blocking_rules
    blocking_rules = {"ips": [], "apps": [], "domains": [], "ports": []}
    return jsonify({"message": "Rules cleared"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print("=" * 55)
    print("  Packet Analyzer Web UI")
    print(f"  http://127.0.0.1:{port}")
    print("=" * 55)
    app.run(debug=debug, host="0.0.0.0", port=port)
