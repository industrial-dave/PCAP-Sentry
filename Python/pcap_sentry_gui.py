import ipaddress
import json
import math
import os
import queue
import random
import statistics
import sys
import threading
import urllib.request
from collections import Counter
from datetime import datetime

from scapy.all import DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:
    DND_FILES = None
    TkinterDnD = None

try:
    import ollama
except Exception:
    ollama = None

try:
    from llama_cpp import Llama
except Exception:
    Llama = None

SIZE_SAMPLE_LIMIT = 50000
DEFAULT_MAX_ROWS = 200000
DEFAULT_MODEL_REPO = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF"
DEFAULT_MODEL_FILENAME = "Meta-Llama-3.1-8B-Instruct-f32.gguf"
IOC_SET_LIMIT = 50000
APP_VERSION = "2026.02.10-3"


def _get_pandas():
    import pandas as pd

    return pd


def _get_figure():
    from matplotlib.figure import Figure

    return Figure


def _get_figure_canvas():
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    return FigureCanvasTkAgg


def _get_app_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


APP_DATA_FALLBACK_NOTICE = None
APP_DATA_DIR = None


def _get_app_data_dir():
    global APP_DATA_FALLBACK_NOTICE
    global APP_DATA_DIR
    fallback_notice = None
    if getattr(sys, "frozen", False):
        base_dir = _get_app_base_dir()
        data_dir = os.path.join(base_dir, "data")
        if _is_writable_dir(base_dir):
            try:
                os.makedirs(data_dir, exist_ok=True)
                APP_DATA_DIR = data_dir
                return data_dir
            except OSError:
                fallback_notice = "App data folder in install directory is not writable."

    base_dir = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.expanduser("~")
    data_dir = os.path.join(base_dir, "PCAP_Sentry")
    os.makedirs(data_dir, exist_ok=True)
    APP_DATA_DIR = data_dir
    if fallback_notice:
        APP_DATA_FALLBACK_NOTICE = f"{fallback_notice} Using {data_dir} instead."
    return data_dir


def _is_writable_dir(path):
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False


def _get_default_models_dir():
    base_dir = _get_app_base_dir()
    if _is_writable_dir(base_dir):
        return os.path.join(base_dir, "models")
    return os.path.join(_get_app_data_dir(), "models")


KNOWLEDGE_BASE_FILE = os.path.join(_get_app_data_dir(), "pcap_knowledge_base_offline.json")
SETTINGS_FILE = os.path.join(_get_app_data_dir(), "settings.json")
DEFAULT_MODEL_PATH = os.path.join(_get_default_models_dir(), DEFAULT_MODEL_FILENAME)


def _default_settings():
    return {
        "max_rows": DEFAULT_MAX_ROWS,
        "parse_http": True,
        "use_llm": ollama is not None,
        "use_gpu": True,
        "model_path": DEFAULT_MODEL_PATH,
        "backup_dir": os.path.dirname(KNOWLEDGE_BASE_FILE),
        "theme": "system",
        "ignored_model_versions": [],
        "app_data_notice_shown": False,
    }


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return _default_settings()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default_settings()
        defaults = _default_settings()
        defaults.update(data)
        return defaults
    except Exception:
        return _default_settings()


def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def _model_download_url():
    return f"https://huggingface.co/{DEFAULT_MODEL_REPO}/resolve/main/{DEFAULT_MODEL_FILENAME}"


def _model_download_url_for(filename):
    return f"https://huggingface.co/{DEFAULT_MODEL_REPO}/resolve/main/{filename}"


def _get_latest_model_filename(allow_fallback=True):
    api_url = f"https://huggingface.co/api/models/{DEFAULT_MODEL_REPO}"
    try:
        with urllib.request.urlopen(api_url) as response:
            payload = json.loads(response.read().decode("utf-8"))
        siblings = payload.get("siblings") or []
        gguf_files = []
        for item in siblings:
            name = item.get("rfilename")
            if name and name.lower().endswith(".gguf"):
                gguf_files.append(item)
        if not gguf_files:
            return DEFAULT_MODEL_FILENAME if allow_fallback else None
        for item in gguf_files:
            if item.get("rfilename") == DEFAULT_MODEL_FILENAME:
                return DEFAULT_MODEL_FILENAME
        def sort_key(entry):
            return entry.get("lastModified") or ""
        gguf_files.sort(key=sort_key, reverse=True)
        latest = gguf_files[0].get("rfilename")
        return latest or (DEFAULT_MODEL_FILENAME if allow_fallback else None)
    except Exception:
        return DEFAULT_MODEL_FILENAME if allow_fallback else None


def _download_file(url, dest_path, progress_cb=None, chunk_size=1024 * 1024):
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with urllib.request.urlopen(url) as response:
        total = response.length or response.getheader("Content-Length")
        total = int(total) if total else None
        downloaded = 0
        with open(dest_path, "wb") as out_file:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                if progress_cb and total:
                    progress = min(99.0, downloaded / total * 100.0)
                    progress_cb(progress, None, downloaded, total)
    if progress_cb:
        progress_cb(100.0, 0, downloaded if total else None, total)
    return dest_path


def _format_bytes(value):
    if value is None:
        return ""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024.0


def _default_kb():
    return {"safe": [], "malicious": [], "ioc": {"ips": [], "domains": [], "hashes": []}}


def load_knowledge_base():
    if not os.path.exists(KNOWLEDGE_BASE_FILE):
        return _default_kb()
    try:
        with open(KNOWLEDGE_BASE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _default_kb()
        data.setdefault("safe", [])
        data.setdefault("malicious", [])
        data.setdefault("ioc", {"ips": [], "domains": [], "hashes": []})
        data["ioc"].setdefault("ips", [])
        data["ioc"].setdefault("domains", [])
        data["ioc"].setdefault("hashes", [])
        return data
    except Exception:
        return _default_kb()


def save_knowledge_base(data):
    with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _normalize_ioc_item(item):
    text = item.strip().lower()
    if not text:
        return None, None

    if text.startswith("http://") or text.startswith("https://"):
        text = text.split("://", 1)[1]
    if "/" in text:
        text = text.split("/", 1)[0]

    try:
        ipaddress.ip_address(text)
        return "ips", text
    except ValueError:
        pass

    if ":" in text and text.count(":") == 1:
        text = text.split(":", 1)[0]

    if "." in text:
        return "domains", text

    if all(c in "0123456789abcdef" for c in text) and len(text) in (32, 40, 64):
        return "hashes", text

    return None, None


def _parse_ioc_text(raw_text):
    iocs = {"ips": set(), "domains": set(), "hashes": set()}
    for line in raw_text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        cleaned = cleaned.replace(",", " ")
        for token in cleaned.split():
            key, value = _normalize_ioc_item(token)
            if key:
                iocs[key].add(value)
    return iocs


def load_iocs_from_file(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        iocs = {"ips": set(), "domains": set(), "hashes": set()}
        for key in ("ips", "domains", "hashes"):
            values = parsed.get(key, [])
            if isinstance(values, list):
                for item in values:
                    key_name, value = _normalize_ioc_item(str(item))
                    if key_name:
                        iocs[key_name].add(value)
        return iocs

    if isinstance(parsed, list):
        return _parse_ioc_text("\n".join(str(item) for item in parsed))

    return _parse_ioc_text(raw)


def merge_iocs_into_kb(kb, new_iocs):
    for key in ("ips", "domains", "hashes"):
        combined = set(kb.get("ioc", {}).get(key, [])) | set(new_iocs.get(key, set()))
        kb["ioc"][key] = sorted(combined)
    return kb


FEATURE_NAMES = [
    "packet_count",
    "avg_size",
    "dns_query_count",
    "http_request_count",
    "unique_http_hosts",
    "proto_tcp",
    "proto_udp",
    "proto_other",
    "top_port_1",
    "top_port_2",
    "top_port_3",
    "top_port_4",
    "top_port_5",
]


def _vector_from_features(features):
    proto = features.get("proto_ratio", {})
    top_ports = features.get("top_ports", [])

    def port_at(idx):
        if idx < len(top_ports):
            return float(top_ports[idx])
        return 0.0

    return [
        float(features.get("packet_count", 0.0)),
        float(features.get("avg_size", 0.0)),
        float(features.get("dns_query_count", 0.0)),
        float(features.get("http_request_count", 0.0)),
        float(features.get("unique_http_hosts", 0.0)),
        float(proto.get("TCP", 0.0)),
        float(proto.get("UDP", 0.0)),
        float(proto.get("Other", 0.0)),
        port_at(0),
        port_at(1),
        port_at(2),
        port_at(3),
        port_at(4),
    ]


def _compute_normalizer(vectors):
    if not vectors:
        return None
    columns = list(zip(*vectors))
    means = [sum(col) / len(col) for col in columns]
    stds = [statistics.pstdev(col) or 1.0 for col in columns]
    return {"mean": means, "std": stds}


def _normalize_vector(vector, normalizer):
    return [
        (value - mean) / std
        for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"])
    ]


def compute_baseline_from_kb(kb):
    safe_vectors = [_vector_from_features(entry["features"]) for entry in kb.get("safe", [])]
    if not safe_vectors:
        return None
    normalizer = _compute_normalizer(safe_vectors)
    return {"normalizer": normalizer, "vectors": safe_vectors}


def anomaly_score(vector, baseline):
    if baseline is None:
        return None, []
    normalizer = baseline["normalizer"]
    zscores = []
    for value, mean, std in zip(vector, normalizer["mean"], normalizer["std"]):
        z = abs(value - mean) / (std or 1.0)
        zscores.append(z)

    capped = [min(z, 4.0) for z in zscores]
    score = sum(capped) / max(len(capped), 1) / 4.0 * 100.0

    top = sorted(enumerate(zscores), key=lambda item: item[1], reverse=True)[:3]
    reasons = [f"{FEATURE_NAMES[idx]} z={value:.1f}" for idx, value in top if value > 0]
    return round(score, 1), reasons


def classify_vector(vector, kb):
    safe_entries = kb.get("safe", [])
    mal_entries = kb.get("malicious", [])
    if not safe_entries or not mal_entries:
        return None

    safe_vectors = [_vector_from_features(entry["features"]) for entry in safe_entries]
    mal_vectors = [_vector_from_features(entry["features"]) for entry in mal_entries]
    all_vectors = safe_vectors + mal_vectors
    normalizer = _compute_normalizer(all_vectors)

    safe_norm = [_normalize_vector(vec, normalizer) for vec in safe_vectors]
    mal_norm = [_normalize_vector(vec, normalizer) for vec in mal_vectors]
    target = _normalize_vector(vector, normalizer)

    def centroid(vectors):
        cols = list(zip(*vectors))
        return [sum(col) / len(col) for col in cols]

    def distance(a, b):
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    safe_centroid = centroid(safe_norm)
    mal_centroid = centroid(mal_norm)
    dist_safe = distance(target, safe_centroid)
    dist_mal = distance(target, mal_centroid)
    if dist_safe + dist_mal == 0:
        prob_mal = 0.5
    else:
        prob_mal = dist_safe / (dist_safe + dist_mal)
    score = round(prob_mal * 100.0, 1)
    return {"score": score, "dist_safe": dist_safe, "dist_mal": dist_mal}


def _domain_matches(domain, ioc_domains):
    if domain in ioc_domains:
        return domain
    for ioc_domain in ioc_domains:
        if domain.endswith("." + ioc_domain):
            return ioc_domain
    return None


def match_iocs(stats, iocs):
    matches = {"ips": set(), "domains": set()}
    ioc_ips = set(iocs.get("ips", []))
    ioc_domains = set(iocs.get("domains", []))

    if ioc_ips:
        for ip in stats.get("unique_src_list", []):
            if ip in ioc_ips:
                matches["ips"].add(ip)
        for ip in stats.get("unique_dst_list", []):
            if ip in ioc_ips:
                matches["ips"].add(ip)

    if ioc_domains:
        for domain in stats.get("dns_queries", []):
            match = _domain_matches(domain.lower(), ioc_domains)
            if match:
                matches["domains"].add(match)
        for domain in stats.get("http_hosts", []):
            match = _domain_matches(domain.lower(), ioc_domains)
            if match:
                matches["domains"].add(match)

    return {"ips": sorted(matches["ips"]), "domains": sorted(matches["domains"])}


def summarize_stats(stats):
    top_ports = stats.get("top_ports", [])
    proto = stats.get("protocol_counts", {})
    dns_count = stats.get("dns_query_count", 0)
    http_count = stats.get("http_request_count", 0)
    return (
        f"Packets: {stats.get('packet_count', 0)}, "
        f"Avg Size: {stats.get('avg_size', 0):.1f}, "
        f"Top Ports: {top_ports}, "
        f"Protocols: {proto}, "
        f"DNS Queries: {dns_count}, "
        f"HTTP Requests: {http_count}"
    )


def build_features(stats):
    total = stats.get("packet_count", 0) or 1
    proto_counts = stats.get("protocol_counts", {})
    proto_ratio = {k: v / total for k, v in proto_counts.items()}
    top_ports = [p for p, _ in stats.get("top_ports", [])]
    return {
        "packet_count": stats.get("packet_count", 0),
        "avg_size": stats.get("avg_size", 0.0),
        "proto_ratio": proto_ratio,
        "top_ports": top_ports,
        "dns_query_count": stats.get("dns_query_count", 0),
        "http_request_count": stats.get("http_request_count", 0),
        "unique_http_hosts": stats.get("unique_http_hosts", 0),
    }


def similarity_score(target, entry):
    if entry.get("packet_count", 0) == 0 or target.get("packet_count", 0) == 0:
        return 0.0

    target_ports = set(target.get("top_ports", []))
    entry_ports = set(entry.get("top_ports", []))
    port_overlap = len(target_ports & entry_ports) / max(len(target_ports | entry_ports), 1)

    target_proto = target.get("proto_ratio", {})
    entry_proto = entry.get("proto_ratio", {})
    proto_keys = set(target_proto) | set(entry_proto)
    proto_diff = sum(abs(target_proto.get(k, 0) - entry_proto.get(k, 0)) for k in proto_keys)
    proto_similarity = max(0.0, 1.0 - proto_diff)

    size_a = target.get("avg_size", 0.0)
    size_b = entry.get("avg_size", 0.0)
    size_similarity = 1.0 - min(abs(size_a - size_b) / max(size_a, size_b, 1.0), 1.0)

    count_a = target.get("packet_count", 0)
    count_b = entry.get("packet_count", 0)
    count_similarity = 1.0 - min(abs(count_a - count_b) / max(count_a, count_b, 1.0), 1.0)

    dns_a = target.get("dns_query_count", 0)
    dns_b = entry.get("dns_query_count", 0)
    dns_similarity = 1.0 - min(abs(dns_a - dns_b) / max(dns_a, dns_b, 1), 1.0)

    http_a = target.get("http_request_count", 0)
    http_b = entry.get("http_request_count", 0)
    http_similarity = 1.0 - min(abs(http_a - http_b) / max(http_a, http_b, 1), 1.0)

    score = 100.0 * (
        0.3 * port_overlap
        + 0.25 * proto_similarity
        + 0.15 * size_similarity
        + 0.1 * count_similarity
        + 0.1 * dns_similarity
        + 0.1 * http_similarity
    )
    return round(score, 1)


def parse_http_payload(payload):
    if not payload:
        return "", "", ""
    try:
        if not (payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HEAD ")):
            return "", "", ""
        headers = payload.split(b"\r\n")
        request_line = headers[0].decode("latin-1", errors="ignore")
        parts = request_line.split(" ")
        if len(parts) < 2:
            return "", "", ""
        method = parts[0].strip()
        path = parts[1].strip()
        host = ""
        for line in headers[1:]:
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin-1", errors="ignore")
                break
        if host and ":" in host:
            host = host.split(":", 1)[0]
        return host, path, method
    except Exception:
        return "", "", ""


def _maybe_reservoir_append(items, item, limit, seen_count):
    if limit <= 0:
        return
    if len(items) < limit:
        items.append(item)
        return
    j = random.randint(1, seen_count)
    if j <= limit:
        items[j - 1] = item


def _maybe_add_set(items, item, limit, stats):
    if not item:
        return
    if item in items:
        return
    if len(items) >= limit:
        stats["ioc_truncated"] = True
        return
    items.add(item)


def parse_pcap_path(file_path, max_rows=DEFAULT_MAX_ROWS, parse_http=True, progress_cb=None):
    pd = _get_pandas()
    rows = []
    size_samples = []
    should_sample_rows = max_rows > 0
    file_size = 0
    try:
        file_size = os.path.getsize(file_path)
    except OSError:
        file_size = 0
    start_time = datetime.utcnow()
    last_progress_time = start_time
    update_every = 500
    stats = {
        "packet_count": 0,
        "sum_size": 0,
        "protocol_counts": Counter(),
        "port_counts": Counter(),
        "unique_src": set(),
        "unique_dst": set(),
        "dns_query_count": 0,
        "http_request_count": 0,
        "unique_http_hosts": set(),
        "dns_counter": Counter(),
        "dns_queries_set": set(),
        "http_hosts_set": set(),
        "ioc_truncated": False,
    }

    stats_packet_count = stats["packet_count"]
    stats_sum_size = stats["sum_size"]
    proto_counts = stats["protocol_counts"]
    port_counts = stats["port_counts"]
    unique_src = stats["unique_src"]
    unique_dst = stats["unique_dst"]
    dns_counter = stats["dns_counter"]
    dns_queries_set = stats["dns_queries_set"]
    http_hosts_set = stats["http_hosts_set"]
    unique_http_hosts = stats["unique_http_hosts"]

    if progress_cb and file_size:
        progress_cb(0.0, None, 0, file_size)

    with PcapReader(file_path) as pcap:
        for pkt in pcap:
            ip_layer = pkt.getlayer(IP)
            if ip_layer is None:
                continue
            stats_packet_count += 1
            pkt_size = len(pkt)
            stats_sum_size += pkt_size
            _maybe_reservoir_append(size_samples, pkt_size, SIZE_SAMPLE_LIMIT, stats_packet_count)

            tcp_layer = pkt.getlayer(TCP)
            udp_layer = None if tcp_layer is not None else pkt.getlayer(UDP)
            if tcp_layer is not None:
                proto = "TCP"
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
            elif udp_layer is not None:
                proto = "UDP"
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
            else:
                proto = "Other"
                sport = 0
                dport = 0
            proto_counts[proto] += 1
            if dport:
                port_counts[dport] += 1

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            unique_src.add(src_ip)
            unique_dst.add(dst_ip)

            dns_query = ""
            dns_layer = pkt.getlayer(DNS)
            if dns_layer is not None:
                try:
                    qd = dns_layer.qd
                    if isinstance(qd, DNSQR):
                        qname = qd.qname
                    elif qd:
                        qname = qd[0].qname
                    else:
                        qname = b""
                    if isinstance(qname, bytes):
                        dns_query = qname.decode("utf-8", errors="ignore").rstrip(".")
                    elif qname:
                        dns_query = str(qname).rstrip(".")
                except Exception:
                    dns_query = ""
            if dns_query:
                stats["dns_query_count"] += 1
                dns_counter[dns_query] += 1
                _maybe_add_set(dns_queries_set, dns_query, IOC_SET_LIMIT, stats)

            http_host = ""
            http_path = ""
            http_method = ""
            if parse_http and tcp_layer is not None:
                raw_layer = pkt.getlayer(Raw)
                if raw_layer is not None and raw_layer.load:
                    http_host, http_path, http_method = parse_http_payload(bytes(raw_layer.load))
            if http_host:
                stats["http_request_count"] += 1
                unique_http_hosts.add(http_host)
                _maybe_add_set(http_hosts_set, http_host, IOC_SET_LIMIT, stats)

            if should_sample_rows:
                row = {
                    "Time": float(pkt.time),
                    "Size": pkt_size,
                    "Proto": proto,
                    "Src": src_ip,
                    "Dst": dst_ip,
                    "SPort": sport,
                    "DPort": dport,
                    "DnsQuery": dns_query,
                    "HttpHost": http_host,
                    "HttpPath": http_path,
                    "HttpMethod": http_method,
                }
                _maybe_reservoir_append(rows, row, max_rows, stats_packet_count)

            if progress_cb and stats_packet_count % update_every == 0:
                now = datetime.utcnow()
                if (now - last_progress_time).total_seconds() >= 0.2:
                    elapsed = (now - start_time).total_seconds()
                    avg_size = stats_sum_size / max(stats_packet_count, 1)
                    est_total = file_size / max(avg_size, 1.0) if file_size else None
                    if file_size:
                        progress = min(99.0, (stats_sum_size / file_size) * 100.0)
                    else:
                        progress = None
                    rate = stats_packet_count / elapsed if elapsed > 0 else 0.0
                    eta = None
                    if est_total and rate > 0:
                        remaining = max(est_total - stats_packet_count, 0)
                        eta = remaining / rate

                    progress_cb(progress, eta, stats_sum_size, file_size)
                    last_progress_time = now

    stats["packet_count"] = stats_packet_count
    stats["sum_size"] = stats_sum_size

    packet_count = stats["packet_count"]
    avg_size = stats["sum_size"] / packet_count if packet_count else 0.0
    median_size = float(statistics.median(size_samples)) if size_samples else 0.0
    top_ports = stats["port_counts"].most_common(5)
    final_stats = {
        "packet_count": int(packet_count),
        "avg_size": float(avg_size),
        "median_size": float(median_size),
        "protocol_counts": {k: int(v) for k, v in stats["protocol_counts"].most_common()},
        "top_ports": [(int(p), int(c)) for p, c in top_ports],
        "unique_src": int(len(stats["unique_src"])),
        "unique_dst": int(len(stats["unique_dst"])),
        "dns_query_count": int(stats["dns_query_count"]),
        "http_request_count": int(stats["http_request_count"]),
        "unique_http_hosts": int(len(stats["unique_http_hosts"])),
        "top_dns": stats["dns_counter"].most_common(5),
        "unique_src_list": sorted(stats["unique_src"]),
        "unique_dst_list": sorted(stats["unique_dst"]),
        "dns_queries": sorted(stats["dns_queries_set"]),
        "http_hosts": sorted(stats["http_hosts_set"]),
        "ioc_truncated": bool(stats["ioc_truncated"]),
    }
    sample_info = {
        "sample_count": len(rows),
        "total_count": packet_count,
    }
    if progress_cb:
        progress_cb(100.0, 0, stats["sum_size"], file_size)
    return pd.DataFrame(rows), final_stats, sample_info


def add_to_knowledge_base(label, stats, features, summary):
    kb = load_knowledge_base()
    entry = {
        "label": label,
        "stats": stats,
        "features": features,
        "summary": summary,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    kb[label].append(entry)
    save_knowledge_base(kb)


def _build_llama_prompt(stats, kb):
    safe = [e["summary"] for e in kb["safe"]]
    malicious = [e["summary"] for e in kb["malicious"]]
    return (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
        "You are an offline malware analyst. Compare the target PCAP stats to known safe and "
        "malicious patterns and provide a short verdict with reasoning.\n"
        "Return: verdict (Safe/Malicious/Suspicious) and 2-4 bullet points.\n"
        "<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
        f"Known safe summaries: {safe}\n"
        f"Known malicious summaries: {malicious}\n"
        f"Target stats: {summarize_stats(stats)}\n"
        "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
    )


def analyze_with_local_llm(stats, kb, llm):
    if llm is None:
        return None
    prompt = _build_llama_prompt(stats, kb)
    response = llm(
        prompt,
        max_tokens=256,
        temperature=0.2,
        top_p=0.9,
        stop=["<|eot_id|>"],
    )
    choices = response.get("choices", [])
    if not choices:
        return None
    return choices[0].get("text", "").strip()


def compute_flow_stats(df):
    pd = _get_pandas()
    if df.empty:
        return pd.DataFrame(columns=["Flow", "Packets", "Bytes", "Duration"])
    flow_cols = ["Src", "Dst", "Proto", "SPort", "DPort"]
    grouped = df.groupby(flow_cols, dropna=False)
    flow_df = grouped.agg(
        Packets=("Size", "count"),
        Bytes=("Size", "sum"),
        Duration=("Time", lambda x: float(x.max() - x.min())),
    ).reset_index()
    flow_df["Flow"] = (
        flow_df["Src"]
        + ":"
        + flow_df["SPort"].astype(str)
        + " -> "
        + flow_df["Dst"]
        + ":"
        + flow_df["DPort"].astype(str)
        + " ("
        + flow_df["Proto"]
        + ")"
    )
    return flow_df.sort_values("Bytes", ascending=False)


def _empty_figure(message):
    Figure = _get_figure()
    fig = Figure(figsize=(6, 4), dpi=100)
    ax = fig.add_subplot(111)
    ax.text(0.5, 0.5, message, ha="center", va="center")
    ax.set_axis_off()
    return fig


def _plot_scatter(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    time_base = df["Time"].min()
    colors = {"TCP": "tab:blue", "UDP": "tab:orange", "Other": "tab:green"}
    for proto, group in df.groupby("Proto"):
        ax.scatter(group["Time"] - time_base, group["Size"], s=6, alpha=0.6, label=proto, c=colors.get(proto))
    ax.set_title("Traffic Spikes")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Packet Size")
    ax.legend(loc="best")
    return fig


def _plot_port_hist(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    for proto, group in df.groupby("Proto"):
        values = group["DPort"]
        values = values[values > 0]
        if not values.empty:
            ax.hist(values, bins=50, alpha=0.5, label=proto)
    ax.set_title("Common Destination Ports")
    ax.set_xlabel("DPort")
    ax.set_ylabel("Count")
    ax.legend(loc="best")
    return fig


def _plot_proto_pie(df):
    if df.empty:
        return _empty_figure("No data")
    Figure = _get_figure()
    fig = Figure(figsize=(6, 4), dpi=100)
    ax = fig.add_subplot(111)
    counts = df["Proto"].value_counts()
    ax.pie(counts.values, labels=counts.index, autopct="%1.1f%%")
    ax.set_title("Protocol Share")
    return fig


def _plot_top_dns(df):
    dns_queries = [q for q in df["DnsQuery"] if q]
    if not dns_queries:
        return _empty_figure("No DNS queries")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top_dns = Counter(dns_queries).most_common(10)
    labels = [q for q, _ in top_dns]
    values = [c for _, c in top_dns]
    ax.bar(labels, values)
    ax.set_title("DNS Query Frequency")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _plot_top_http(df):
    http_hosts = [h for h in df["HttpHost"] if h]
    if not http_hosts:
        return _empty_figure("No HTTP hosts")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top_hosts = Counter(http_hosts).most_common(10)
    labels = [h for h, _ in top_hosts]
    values = [c for _, c in top_hosts]
    ax.bar(labels, values)
    ax.set_title("HTTP Host Frequency")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _plot_top_flows(df):
    flow_df = compute_flow_stats(df)
    if flow_df.empty:
        return _empty_figure("No flows")
    Figure = _get_figure()
    fig = Figure(figsize=(7, 4), dpi=100)
    ax = fig.add_subplot(111)
    top = flow_df.head(10)
    ax.bar(top["Flow"], top["Bytes"])
    ax.set_title("Flow Volume")
    ax.set_ylabel("Bytes")
    ax.tick_params(axis="x", rotation=45)
    return fig


def _add_chart_tab(notebook, title, fig):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)
    FigureCanvasTkAgg = _get_figure_canvas()
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)


class PCAPSentryApp:
    def __init__(self, root):
        self.root = root
        self.root_title = f"PCAP Sentry (Offline GUI) v{APP_VERSION}"
        self.root.title(self.root_title)
        self.root.geometry("1100x750")

        self.settings = load_settings()

        self.theme_var = tk.StringVar(value=self.settings.get("theme", "system"))
        self.colors = {}
        self._apply_theme()

        self.font_title = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        self.font_subtitle = tkfont.Font(family="Segoe UI", size=10)

        self.max_rows_var = tk.IntVar(value=self.settings.get("max_rows", DEFAULT_MAX_ROWS))
        self.parse_http_var = tk.BooleanVar(value=self.settings.get("parse_http", True))
        self.use_llm_var = tk.BooleanVar(value=self.settings.get("use_llm", False) and ollama is not None)
        self.use_gpu_var = tk.BooleanVar(value=self.settings.get("use_gpu", True))
        self.model_path_var = tk.StringVar(value=self.settings.get("model_path", DEFAULT_MODEL_PATH))
        self.status_var = tk.StringVar(value="Ready")
        self.progress_percent_var = tk.StringVar(value="")
        self.sample_note_var = tk.StringVar(value="")
        self.ioc_path_var = tk.StringVar()
        self.ioc_summary_var = tk.StringVar(value="")
        self.backup_dir_var = tk.StringVar(value=self.settings.get("backup_dir", os.path.dirname(KNOWLEDGE_BASE_FILE)))

        self.current_df = None
        self.current_stats = None
        self.current_sample_info = None
        self.llm = None
        self.llm_path = None
        self.busy_count = 0
        self.busy_widgets = []
        self.widget_states = {}
        self.overlay = None
        self.overlay_label = None
        self.overlay_progress = None
        self.overlay_percent_label = None
        self.bg_canvas = None
        self.label_safe_button = None
        self.label_mal_button = None
        self.model_update_checked = False

        self._build_background()

        self._build_header()
        self._build_tabs()
        self._build_status()
        self.root.after(1200, self._check_model_update_on_startup)
        if APP_DATA_FALLBACK_NOTICE and not self.settings.get("app_data_notice_shown"):
            self.root.after(200, self._show_app_data_notice)

    def _show_app_data_notice(self):
        window = tk.Toplevel(self.root)
        window.title("App Data Location")
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=APP_DATA_FALLBACK_NOTICE, wraplength=380, justify="left").pack(anchor="w")
        dont_show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Don't show this again", variable=dont_show_var).pack(anchor="w", pady=(10, 0))

        def close_notice():
            if dont_show_var.get():
                self.settings["app_data_notice_shown"] = True
                save_settings(self.settings)
            window.destroy()

        button_row = ttk.Frame(frame)
        button_row.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(button_row, text="Open folder", command=self._open_app_data_dir).pack(side=tk.LEFT)
        ttk.Button(button_row, text="Copy path", command=self._copy_app_data_dir).pack(side=tk.LEFT, padx=6)
        ttk.Button(button_row, text="OK", command=close_notice).pack(side=tk.RIGHT)
        window.transient(self.root)
        window.grab_set()

    def _open_app_data_dir(self):
        if not APP_DATA_DIR:
            messagebox.showerror("App Data Location", "App data folder is unavailable.")
            return
        try:
            os.startfile(APP_DATA_DIR)
        except OSError as exc:
            messagebox.showerror("App Data Location", f"Failed to open folder: {exc}")

    def _copy_app_data_dir(self):
        if not APP_DATA_DIR:
            messagebox.showerror("App Data Location", "App data folder is unavailable.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(APP_DATA_DIR)

    def _add_ignored_model_version(self, version):
        ignored = list(self.settings.get("ignored_model_versions", []))
        if version and version not in ignored:
            ignored.append(version)
            self.settings["ignored_model_versions"] = ignored
            save_settings(self.settings)

    def _check_model_update_on_startup(self):
        if self.model_update_checked:
            return
        self.model_update_checked = True

        def worker():
            latest_name = _get_latest_model_filename(allow_fallback=False)
            self.root.after(0, lambda: self._handle_model_update_check(latest_name))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_model_update_check(self, latest_name):
        if not latest_name:
            return
        current_path = self.model_path_var.get().strip()
        current_name = os.path.basename(current_path) if current_path else DEFAULT_MODEL_FILENAME
        if latest_name == current_name:
            messagebox.showinfo("Model Update", "Model is already up to date.")
            return
        ignored = set(self.settings.get("ignored_model_versions", []))
        if latest_name in ignored:
            return

        message = (
            "A newer model is available.\n\n"
            f"Current: {current_name}\n"
            f"Latest:  {latest_name}\n\n"
            "Update now?\n\n"
            "Select Cancel to ignore this version."
        )
        choice = messagebox.askyesnocancel("Model Update", message)
        if choice is True:
            self._update_model(latest_name=latest_name, skip_confirm=True)
        elif choice is None:
            self._add_ignored_model_version(latest_name)

    def _build_header(self):
        header = tk.Frame(self.root, bg=self.colors["bg"])
        header.pack(fill=tk.X, padx=12, pady=(12, 6))

        top_row = tk.Frame(header, bg=self.colors["bg"])
        top_row.pack(fill=tk.X)

        title_block = tk.Frame(top_row, bg=self.colors["bg"])
        title_block.pack(side=tk.LEFT)

        tk.Label(
            title_block,
            text="PCAP Sentry",
            font=self.font_title,
            fg=self.colors["text"],
            bg=self.colors["bg"],
        ).pack(anchor=tk.W)
        tk.Label(
            title_block,
            text=f"Offline malware analysis console (v{APP_VERSION})",
            font=self.font_subtitle,
            fg=self.colors["muted"],
            bg=self.colors["bg"],
        ).pack(anchor=tk.W)

        status_text = "Ollama available" if ollama is not None else "Ollama not available"
        status_bg = "#123320" if ollama is not None else "#3a1c1c"
        status_fg = "#9fe2b0" if ollama is not None else "#e6a1a1"
        status_badge = tk.Label(
            top_row,
            text=status_text,
            bg=status_bg,
            fg=status_fg,
            padx=10,
            pady=4,
        )
        status_badge.pack(side=tk.RIGHT)

        toolbar = ttk.Frame(header, padding=(0, 10, 0, 0))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Max packets for visuals:").pack(side=tk.LEFT)
        ttk.Spinbox(toolbar, from_=10000, to=500000, increment=10000, textvariable=self.max_rows_var, width=8).pack(
            side=tk.LEFT, padx=6
        )
        ttk.Checkbutton(toolbar, text="Parse HTTP payloads", variable=self.parse_http_var).pack(side=tk.LEFT, padx=6)
        ttk.Button(toolbar, text="Preferences", command=self._open_preferences).pack(side=tk.RIGHT, padx=6)
        ttk.Button(toolbar, text="Reset Knowledge Base", command=self._reset_kb).pack(side=tk.RIGHT)

        accent = tk.Frame(self.root, bg=self.colors["accent_alt"], height=2)
        accent.pack(fill=tk.X, padx=12, pady=(0, 8))

    def _build_tabs(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.train_tab = ttk.Frame(notebook)
        self.analyze_tab = ttk.Frame(notebook)
        self.kb_tab = ttk.Frame(notebook)

        notebook.add(self.train_tab, text="Train")
        notebook.add(self.analyze_tab, text="Analyze")
        notebook.add(self.kb_tab, text="Knowledge Base")

        self._build_train_tab()
        self._build_analyze_tab()
        self._build_kb_tab()

        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _build_status(self):
        status = ttk.Frame(self.root, padding=6)
        status.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=180)
        self.progress.pack(side=tk.LEFT, padx=6)
        ttk.Label(status, textvariable=self.progress_percent_var, style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Label(status, textvariable=self.status_var).pack(side=tk.LEFT)
        self.eta_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.eta_var, style="Hint.TLabel").pack(side=tk.LEFT, padx=10)
        ttk.Label(status, textvariable=self.sample_note_var).pack(side=tk.RIGHT)

    def _open_preferences(self):
        window = tk.Toplevel(self.root)
        window.title("Preferences")
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Defaults", style="Hint.TLabel").grid(row=0, column=0, sticky="w", columnspan=3)

        ttk.Label(frame, text="Theme:").grid(row=1, column=0, sticky="w", pady=6)
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=["system", "dark", "light"], width=10)
        theme_combo.state(["readonly"])
        theme_combo.grid(row=1, column=1, sticky="w", pady=6)
        ttk.Label(frame, text="(applies after restart)", style="Hint.TLabel").grid(
            row=1, column=2, sticky="w", pady=6
        )

        ttk.Label(frame, text="Max packets for visuals:").grid(row=2, column=0, sticky="w", pady=6)
        max_rows_spin = ttk.Spinbox(
            frame,
            from_=10000,
            to=500000,
            increment=10000,
            textvariable=self.max_rows_var,
            width=10,
        )
        max_rows_spin.grid(row=2, column=1, sticky="w", pady=6)

        ttk.Checkbutton(frame, text="Parse HTTP payloads", variable=self.parse_http_var).grid(
            row=3, column=0, sticky="w", pady=6, columnspan=2
        )

        llm_toggle = ttk.Checkbutton(frame, text="Use local LLM (Ollama)", variable=self.use_llm_var)
        llm_toggle.grid(row=4, column=0, sticky="w", pady=6, columnspan=2)
        if ollama is None:
            llm_toggle.configure(state=tk.DISABLED)

        ttk.Checkbutton(frame, text="Use GPU if available", variable=self.use_gpu_var).grid(
            row=5, column=0, sticky="w", pady=6, columnspan=2
        )

        ttk.Label(frame, text="Default model path:").grid(row=6, column=0, sticky="w", pady=6)
        model_entry = ttk.Entry(frame, textvariable=self.model_path_var, width=48)
        model_entry.grid(row=6, column=1, sticky="w", pady=6)
        ttk.Button(frame, text="Browse", command=self._browse_model).grid(row=6, column=2, padx=6, pady=6)
        ttk.Button(frame, text="Update Model", command=self._update_model).grid(row=6, column=3, padx=6, pady=6)

        ttk.Label(frame, text="Backup directory:").grid(row=7, column=0, sticky="w", pady=6)
        backup_entry = ttk.Entry(frame, textvariable=self.backup_dir_var, width=48)
        backup_entry.grid(row=7, column=1, sticky="w", pady=6)
        ttk.Button(frame, text="Browse", command=self._browse_backup_dir).grid(row=7, column=2, padx=6, pady=6)

        button_row = ttk.Frame(frame)
        button_row.grid(row=8, column=0, columnspan=4, sticky="e", pady=(10, 0))
        ttk.Button(button_row, text="Reset to Defaults", command=self._reset_preferences).pack(side=tk.LEFT)
        ttk.Button(button_row, text="Cancel", command=window.destroy).pack(side=tk.RIGHT, padx=6)
        ttk.Button(
            button_row,
            text="Save",
            command=lambda: self._save_preferences(window),
        ).pack(side=tk.RIGHT)

        window.grab_set()

    def _save_preferences(self, window):
        self._save_settings_from_vars()
        window.destroy()

    def _save_settings_from_vars(self):
        settings = {
            "max_rows": int(self.max_rows_var.get()),
            "parse_http": bool(self.parse_http_var.get()),
            "use_llm": bool(self.use_llm_var.get()),
            "use_gpu": bool(self.use_gpu_var.get()),
            "model_path": self.model_path_var.get().strip(),
            "backup_dir": self.backup_dir_var.get().strip(),
            "theme": self.theme_var.get().strip().lower() or "system",
            "ignored_model_versions": list(self.settings.get("ignored_model_versions", [])),
            "app_data_notice_shown": bool(self.settings.get("app_data_notice_shown")),
        }
        self.settings = settings
        save_settings(settings)

    def _reset_preferences(self):
        confirm = messagebox.askyesno(
            "Preferences",
            "Reset preferences to defaults?",
        )
        if not confirm:
            return

        defaults = _default_settings()
        self.max_rows_var.set(defaults["max_rows"])
        self.parse_http_var.set(defaults["parse_http"])
        self.use_llm_var.set(defaults["use_llm"] and ollama is not None)
        self.use_gpu_var.set(defaults["use_gpu"])
        self.model_path_var.set(defaults["model_path"])
        self.backup_dir_var.set(defaults["backup_dir"])
        self.theme_var.set(defaults["theme"])
        self._save_settings_from_vars()

    def _browse_backup_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.backup_dir_var.set(path)

    def _build_train_tab(self):
        container = ttk.Frame(self.train_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        safe_frame = ttk.LabelFrame(container, text="Known Safe PCAP", padding=10)
        safe_frame.pack(fill=tk.X, pady=8)

        self.safe_path_var = tk.StringVar()
        self.safe_entry = ttk.Entry(safe_frame, textvariable=self.safe_path_var, width=90)
        self.safe_entry.pack(side=tk.LEFT, padx=6)
        self.safe_browse = ttk.Button(safe_frame, text="Browse", command=lambda: self._browse_file(self.safe_path_var))
        self.safe_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.safe_add_button = ttk.Button(safe_frame, text="Add to Safe", command=lambda: self._train("safe"))
        self.safe_add_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="Tip: Drag and drop a .pcap file into the path field.", style="Hint.TLabel").pack(
            anchor=tk.W, padx=6
        )
        ttk.Label(
            container,
            text="Note: Large PCAP files can take a few minutes to parse.",
            style="Hint.TLabel",
        ).pack(anchor=tk.W, padx=6)

        mal_frame = ttk.LabelFrame(container, text="Known Malware PCAP", padding=10)
        mal_frame.pack(fill=tk.X, pady=8)

        self.mal_path_var = tk.StringVar()
        self.mal_entry = ttk.Entry(mal_frame, textvariable=self.mal_path_var, width=90)
        self.mal_entry.pack(side=tk.LEFT, padx=6)
        self.mal_browse = ttk.Button(mal_frame, text="Browse", command=lambda: self._browse_file(self.mal_path_var))
        self.mal_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.mal_add_button = ttk.Button(mal_frame, text="Add to Malware", command=lambda: self._train("malicious"))
        self.mal_add_button.pack(
            side=tk.LEFT, padx=6
        )

    def _build_analyze_tab(self):
        container = ttk.Frame(self.analyze_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        file_frame = ttk.LabelFrame(container, text="Target PCAP", padding=10)
        file_frame.pack(fill=tk.X)

        self.target_path_var = tk.StringVar()
        self.target_entry = ttk.Entry(file_frame, textvariable=self.target_path_var, width=90)
        self.target_entry.pack(side=tk.LEFT, padx=6)
        target_browse = ttk.Button(file_frame, text="Browse", command=lambda: self._browse_file(self.target_path_var))
        target_browse.pack(
            side=tk.LEFT, padx=6
        )
        self.analyze_button = ttk.Button(file_frame, text="Analyze", command=self._analyze)
        self.analyze_button.pack(side=tk.LEFT, padx=6)

        ttk.Label(container, text="Tip: Drag and drop a .pcap file into the path field.", style="Hint.TLabel").pack(
            anchor=tk.W, padx=6
        )

        opts_frame = ttk.Frame(container, padding=(0, 8))
        opts_frame.pack(fill=tk.X)
        ttk.Checkbutton(opts_frame, text="Use local LLM (Ollama)", variable=self.use_llm_var).pack(side=tk.LEFT)

        llm_frame = ttk.LabelFrame(container, text="Local LLM (GGUF)", padding=10)
        llm_frame.pack(fill=tk.X, pady=6)

        ttk.Label(llm_frame, text="Model path:").pack(side=tk.LEFT)
        self.model_entry = ttk.Entry(llm_frame, textvariable=self.model_path_var, width=70)
        self.model_entry.pack(side=tk.LEFT, padx=6)
        model_browse = ttk.Button(llm_frame, text="Browse", command=self._browse_model)
        model_browse.pack(side=tk.LEFT, padx=6)
        ttk.Checkbutton(llm_frame, text="Use GPU if available", variable=self.use_gpu_var).pack(side=tk.LEFT, padx=6)

        ttk.Label(
            container,
            text="Tip: Drag and drop a .gguf model into the model path field.",
            style="Hint.TLabel",
        ).pack(anchor=tk.W, padx=6)

        result_frame = ttk.LabelFrame(container, text="Results", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=8)

        self.result_text = tk.Text(result_frame, height=12)
        self._style_text(self.result_text)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        label_frame = ttk.LabelFrame(container, text="Label Current Capture", padding=10)
        label_frame.pack(fill=tk.X, pady=6)
        self.label_safe_button = ttk.Button(
            label_frame,
            text="Mark as Safe",
            command=lambda: self._label_current("safe"),
            state=tk.DISABLED,
        )
        self.label_safe_button.pack(side=tk.LEFT, padx=6)
        self.label_mal_button = ttk.Button(
            label_frame,
            text="Mark as Malicious",
            command=lambda: self._label_current("malicious"),
            state=tk.DISABLED,
        )
        self.label_mal_button.pack(side=tk.LEFT, padx=6)
        ttk.Label(label_frame, text="Adds this capture to the knowledge base.", style="Hint.TLabel").pack(
            side=tk.LEFT, padx=6
        )

        flow_frame = ttk.LabelFrame(container, text="Flow Summary", padding=10)
        flow_frame.pack(fill=tk.BOTH, expand=True, pady=8)

        columns = ("Flow", "Packets", "Bytes", "Duration")
        self.flow_table = ttk.Treeview(flow_frame, columns=columns, show="headings", height=8)
        for col in columns:
            self.flow_table.heading(col, text=col)
            self.flow_table.column(col, width=220 if col == "Flow" else 90, anchor=tk.W)
        self.flow_table.pack(fill=tk.BOTH, expand=True)

        self.charts_button = ttk.Button(container, text="Open Charts", command=self._open_charts, state=tk.DISABLED)
        self.charts_button.pack(anchor=tk.E)

        self.busy_widgets.extend(
            [
                self.safe_browse,
                self.safe_add_button,
                self.mal_browse,
                self.mal_add_button,
                target_browse,
                self.analyze_button,
                model_browse,
                self.charts_button,
                self.label_safe_button,
                self.label_mal_button,
            ]
        )

        self._setup_drag_drop()

    def _build_kb_tab(self):
        container = ttk.Frame(self.kb_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container)
        header.pack(fill=tk.X)
        self.kb_summary_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.kb_summary_var).pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self._refresh_kb).pack(side=tk.RIGHT)
        ttk.Button(header, text="Restore", command=self._restore_kb).pack(side=tk.RIGHT, padx=6)
        ttk.Button(header, text="Backup", command=self._backup_kb).pack(side=tk.RIGHT, padx=6)

        ioc_frame = ttk.LabelFrame(container, text="IoC Feed", padding=10)
        ioc_frame.pack(fill=tk.X, pady=6)
        ttk.Label(ioc_frame, text="IoC file:").pack(side=tk.LEFT)
        ioc_entry = ttk.Entry(ioc_frame, textvariable=self.ioc_path_var, width=70)
        ioc_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Browse", command=self._browse_ioc).pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Import", command=self._load_ioc_file).pack(side=tk.LEFT, padx=6)
        ttk.Button(ioc_frame, text="Clear", command=self._clear_iocs).pack(side=tk.LEFT, padx=6)
        ttk.Label(ioc_frame, textvariable=self.ioc_summary_var, style="Hint.TLabel").pack(side=tk.LEFT, padx=6)

        self.kb_text = tk.Text(container)
        self._style_text(self.kb_text)
        self.kb_text.pack(fill=tk.BOTH, expand=True, pady=8)
        self._refresh_kb()

    def _browse_file(self, var):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _browse_model(self):
        path = filedialog.askopenfilename(filetypes=[("GGUF model", "*.gguf"), ("All files", "*.*")])
        if path:
            self.model_path_var.set(path)

    def _browse_ioc(self):
        path = filedialog.askopenfilename(filetypes=[("IoC files", "*.json;*.txt"), ("All files", "*.*")])
        if path:
            self.ioc_path_var.set(path)

    def _set_busy(self, busy=True, message="Working..."):
        if busy:
            self.busy_count += 1
            if self.busy_count == 1:
                self.status_var.set(message)
                self._reset_progress()
                self.progress.start(10)
                self.root.configure(cursor="watch")
                self.root.title(f"{self.root_title} - Working...")
                self.widget_states = {w: str(w["state"]) for w in self.busy_widgets}
                for widget in self.busy_widgets:
                    widget.configure(state=tk.DISABLED)
                self._show_overlay(message)
            else:
                self.status_var.set(message)
                self._update_overlay_message(message)
        else:
            self.busy_count = max(0, self.busy_count - 1)
            if self.busy_count == 0:
                self._reset_progress()
                self.status_var.set("Ready")
                self.root.configure(cursor="")
                self.root.title(self.root_title)
                for widget in self.busy_widgets:
                    prior = self.widget_states.get(widget, "normal")
                    widget.configure(state=prior)
                self._hide_overlay()

    def _reset_progress(self):
        self.progress.stop()
        self.progress.configure(mode="indeterminate", maximum=100)
        self.progress["value"] = 0
        self.progress_percent_var.set("")
        self.eta_var.set("")
        if self.overlay_progress is not None:
            self.overlay_progress.stop()
            self.overlay_progress.configure(mode="indeterminate", maximum=100)
            self.overlay_progress["value"] = 0
            self.overlay_progress.start(10)

    def _format_eta(self, seconds):
        if seconds is None:
            return ""
        seconds = max(0, int(seconds))
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        if hours:
            return f"{hours:d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"

    def _set_progress(self, percent, eta_seconds=None, label=None, processed=None, total=None):
        if percent is None:
            self.progress_percent_var.set("")
            return
        self.progress.stop()
        self.progress.configure(mode="determinate", maximum=100)
        percent_value = min(max(percent, 0.0), 100.0)
        self.progress["value"] = percent_value
        self.progress_percent_var.set(f"{percent_value:.0f}%")
        eta_text = self._format_eta(eta_seconds)
        self.eta_var.set(f"ETA {eta_text}" if eta_text else "")
        if label:
            status_text = f"{label} {percent:.0f}%"
            if processed is not None and total:
                status_text = f"{label} {percent:.0f}% ({_format_bytes(processed)} / {_format_bytes(total)})"
            self.status_var.set(status_text)
            if self.overlay_label is not None:
                self.overlay_label.configure(text=status_text)
        if self.overlay_progress is not None:
            self.overlay_progress.stop()
            self.overlay_progress.configure(mode="determinate", maximum=100)
            self.overlay_progress["value"] = min(max(percent, 0.0), 100.0)

    def _apply_theme(self):
        theme = self._resolve_theme()
        if theme == "light":
            self.colors = {
                "bg": "#f5f7fb",
                "panel": "#ffffff",
                "text": "#12141a",
                "muted": "#5d6776",
                "accent": "#2b7cbf",
                "accent_alt": "#1f5f95",
                "border": "#d7dbe2",
                "danger": "#b84a3f",
                "neon": "#a02f8f",
                "neon_alt": "#2a88a6",
                "bg_wave": "#dbe3ef",
                "bg_node": "#c9d3e3",
                "bg_hex": "#c2ccdb",
            }
        else:
            self.colors = {
                "bg": "#0a0c11",
                "panel": "#111621",
                "text": "#e6e6e6",
                "muted": "#9aa3b2",
                "accent": "#3fa9f5",
                "accent_alt": "#2b7cbf",
                "border": "#222938",
                "danger": "#e76f51",
                "neon": "#c235a8",
                "neon_alt": "#2aa5c9",
                "bg_wave": "#1b2a3f",
                "bg_node": "#223551",
                "bg_hex": "#142133",
            }

        self.root.configure(bg=self.colors["bg"])
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=self.colors["bg"])
        style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("Hint.TLabel", background=self.colors["bg"], foreground=self.colors["muted"])
        style.configure(
            "TButton",
            background=self.colors["accent"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            focusthickness=1,
            focuscolor=self.colors["accent_alt"],
            padding=6,
        )
        style.map(
            "TButton",
            background=[("active", self.colors["accent_alt"]), ("disabled", self.colors["border"])],
            foreground=[("disabled", self.colors["muted"])],
        )

        style.configure("TCheckbutton", background=self.colors["bg"], foreground=self.colors["text"])
        style.map("TCheckbutton", foreground=[("disabled", self.colors["muted"])])

        style.configure("TLabelframe", background=self.colors["bg"], foreground=self.colors["text"])
        style.configure("TLabelframe.Label", background=self.colors["bg"], foreground=self.colors["text"])

        style.configure("TNotebook", background=self.colors["bg"], bordercolor=self.colors["border"])
        style.configure("TNotebook.Tab", background=self.colors["panel"], foreground=self.colors["text"], padding=6)
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["accent_alt"]), ("active", self.colors["accent"])]
        )

        style.configure(
            "TEntry",
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            insertcolor=self.colors["text"],
        )
        style.configure(
            "TSpinbox",
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
            insertcolor=self.colors["text"],
        )

        style.configure(
            "Treeview",
            background=self.colors["panel"],
            fieldbackground=self.colors["panel"],
            foreground=self.colors["text"],
            bordercolor=self.colors["border"],
        )
        style.configure(
            "Treeview.Heading",
            background=self.colors["bg"],
            foreground=self.colors["text"],
        )
        style.map(
            "Treeview",
            background=[("selected", self.colors["accent_alt"])],
            foreground=[("selected", self.colors["text"])],
        )

        style.configure(
            "TProgressbar",
            background=self.colors["accent"],
            troughcolor=self.colors["panel"],
            bordercolor=self.colors["border"],
        )

    def _resolve_theme(self):
        theme = "system"
        if hasattr(self, "theme_var"):
            theme = self.theme_var.get().strip().lower() or "system"
        else:
            theme = self.settings.get("theme", "system")

        if theme == "system":
            return self._detect_system_theme()
        if theme in ("dark", "light"):
            return theme
        return "dark"

    def _detect_system_theme(self):
        if sys.platform.startswith("win"):
            try:
                import winreg

                key_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                    value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
                return "light" if value else "dark"
            except Exception:
                return "dark"
        return "dark"

    def _build_background(self):
        canvas = tk.Canvas(self.root, highlightthickness=0, bd=0, bg=self.colors["bg"])
        canvas.place(x=0, y=0, relwidth=1, relheight=1)
        canvas.tk.call("lower", canvas._w)
        canvas.bind("<Configure>", self._draw_background)
        self.bg_canvas = canvas

    def _draw_background(self, _event=None):
        if self.bg_canvas is None:
            return
        w = self.bg_canvas.winfo_width()
        h = self.bg_canvas.winfo_height()
        if w <= 1 or h <= 1:
            return

        self.bg_canvas.delete("all")

        # Base gradient
        steps = 18
        for i in range(steps):
            ratio = i / max(steps - 1, 1)
            r = int(10 + (20 - 10) * ratio)
            g = int(12 + (16 - 12) * ratio)
            b = int(18 + (26 - 18) * ratio)
            color = f"#{r:02x}{g:02x}{b:02x}"
            y0 = int(h * i / steps)
            y1 = int(h * (i + 1) / steps)
            self.bg_canvas.create_rectangle(0, y0, w, y1, fill=color, outline=color)

        # Neon horizon glow
        glow_y = int(h * 0.65)
        self.bg_canvas.create_oval(-w * 0.2, glow_y - h * 0.1, w * 1.2, glow_y + h * 0.4,
                       fill="", outline=self.colors["neon"], width=1)
        self.bg_canvas.create_oval(-w * 0.1, glow_y - h * 0.05, w * 1.1, glow_y + h * 0.3,
                       fill="", outline=self.colors["neon_alt"], width=1)

        # Grid lines
        grid_color = "#141b26"
        for x in range(0, w, 60):
            self.bg_canvas.create_line(x, glow_y, x, h, fill=grid_color)
        for y in range(glow_y, h, 40):
            self.bg_canvas.create_line(0, y, w, y, fill=grid_color)

        # Diagonal neon accents
        self.bg_canvas.create_line(0, glow_y - 80, w, glow_y + 120, fill=self.colors["neon_alt"], width=1)
        self.bg_canvas.create_line(0, glow_y - 120, w, glow_y + 80, fill=self.colors["neon"], width=1)

        # PCAP-style waveform
        wave_color = self.colors.get("bg_wave", "#1b2a3f")
        points = []
        step = max(40, w // 18)
        amplitude = max(18, h // 22)
        baseline = int(h * 0.28)
        for x in range(0, w + step, step):
            offset = ((x // step) % 2) * 2 - 1
            y = baseline + offset * amplitude
            points.extend([x, y])
        if len(points) >= 4:
            self.bg_canvas.create_line(*points, fill=wave_color, width=2)

        # Packet nodes
        node_color = self.colors.get("bg_node", "#223551")
        for x in range(80, w, 220):
            self.bg_canvas.create_oval(x, baseline - 6, x + 10, baseline + 4, outline=node_color, width=2)

        # Hex dump motif
        hex_color = self.colors.get("bg_hex", "#142133")
        hex_rows = min(6, max(2, h // 140))
        hex_cols = min(6, max(3, w // 200))
        hex_text = "4f 52 4f 4c 2d 50 43 41 50"
        for row in range(hex_rows):
            for col in range(hex_cols):
                x = 40 + col * 180
                y = int(h * 0.72) + row * 22
                self.bg_canvas.create_text(x, y, anchor="w", text=hex_text, fill=hex_color, font=("Consolas", 9))

    def _setup_drag_drop(self):
        if DND_FILES is None or TkinterDnD is None:
            return

        def bind_drop(widget, setter):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", lambda e: setter(self._extract_drop_path(e.data)))

        bind_drop(self.safe_entry, self.safe_path_var.set)
        bind_drop(self.mal_entry, self.mal_path_var.set)
        bind_drop(self.target_entry, self.target_path_var.set)
        bind_drop(self.model_entry, self.model_path_var.set)

    def _extract_drop_path(self, data):
        if not data:
            return ""
        text = data.strip()
        if text.startswith("{") and text.endswith("}"):
            text = text[1:-1]
        if " " in text:
            text = text.split()[0]
        return text

    def _style_text(self, widget):
        widget.configure(
            background=self.colors["panel"],
            foreground=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent_alt"],
            selectforeground=self.colors["text"],
            borderwidth=1,
            relief="solid",
        )

    def _show_overlay(self, message):
        if self.overlay is not None:
            self._update_overlay_message(message)
            return

        overlay = tk.Toplevel(self.root)
        overlay.transient(self.root)
        overlay.title("Working")
        overlay.resizable(False, False)
        overlay.attributes("-topmost", True)
        overlay.configure(bg=self.colors["bg"])

        frame = ttk.Frame(overlay, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        label = ttk.Label(frame, text=message)
        label.pack(pady=(0, 8))

        progress = ttk.Progressbar(frame, mode="indeterminate", length=240)
        progress.pack()
        progress.start(10)

        percent_label = ttk.Label(frame, textvariable=self.progress_percent_var, style="Hint.TLabel")
        percent_label.pack(pady=(6, 0))

        overlay.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - overlay.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - overlay.winfo_height()) // 2
        overlay.geometry(f"+{max(x, 0)}+{max(y, 0)}")

        self.overlay = overlay
        self.overlay_label = label
        self.overlay_progress = progress
        self.overlay_percent_label = percent_label

        try:
            overlay.grab_set()
        except tk.TclError:
            pass

    def _update_overlay_message(self, message):
        if self.overlay_label is not None:
            self.overlay_label.configure(text=message)

    def _hide_overlay(self):
        if self.overlay is None:
            return
        try:
            self.overlay.grab_release()
        except tk.TclError:
            pass
        if self.overlay_progress is not None:
            self.overlay_progress.stop()
        self.overlay.destroy()
        self.overlay = None
        self.overlay_label = None
        self.overlay_progress = None
        self.overlay_percent_label = None

    def _run_task(self, func, on_success, on_error=None, message="Working...", progress_label=None):
        self._set_busy(True, message)
        q = queue.Queue()

        def progress_cb(percent, eta_seconds=None, processed=None, total=None):
            q.put(
                (
                    "progress",
                    {
                        "percent": percent,
                        "eta": eta_seconds,
                        "processed": processed,
                        "total": total,
                    },
                )
            )

        def worker():
            try:
                if progress_label:
                    q.put(("ok", func(progress_cb)))
                else:
                    q.put(("ok", func()))
            except Exception as exc:
                q.put(("err", exc))

        threading.Thread(target=worker, daemon=True).start()

        def check():
            done = False
            payload = None
            error = None
            latest_progress = None
            try:
                for _ in range(50):
                    status, item = q.get_nowait()
                    if status == "progress":
                        latest_progress = item
                    elif status == "ok":
                        done = True
                        payload = item
                        break
                    elif status == "err":
                        done = True
                        error = item
                        break
            except queue.Empty:
                pass

            if latest_progress is not None:
                self._set_progress(
                    latest_progress.get("percent"),
                    latest_progress.get("eta"),
                    progress_label,
                    processed=latest_progress.get("processed"),
                    total=latest_progress.get("total"),
                )

            if done:
                self._set_busy(False)
                if error is None:
                    on_success(payload)
                else:
                    if on_error:
                        on_error(error)
                    else:
                        messagebox.showerror("Error", str(error))
            else:
                self.root.after(100, check)

        self.root.after(100, check)

    def _download_default_model(self, progress_cb=None, filename=None):
        target_name = filename or DEFAULT_MODEL_FILENAME
        url = _model_download_url_for(target_name)
        dest_path = os.path.join(_get_default_models_dir(), target_name)
        return _download_file(url, dest_path, progress_cb=progress_cb)

    def _update_model(self, latest_name=None, skip_confirm=False):
        current_path = self.model_path_var.get().strip()
        current_name = os.path.basename(current_path) if current_path else DEFAULT_MODEL_FILENAME
        target_name = latest_name or _get_latest_model_filename()

        if target_name == current_name:
            messagebox.showinfo("Update Model", "Model is already up to date.")
            return

        if not skip_confirm:
            message = (
                "Update the GGUF model?\n\n"
                f"Current: {current_name}\n"
                f"New:     {target_name}\n\n"
                "This will download and replace the model file."
            )
            if not messagebox.askyesno("Update Model", message):
                return

        def task(progress_cb=None):
            dest_path = os.path.join(_get_default_models_dir(), target_name)
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except Exception:
                    pass
            return self._download_default_model(progress_cb=progress_cb, filename=target_name)

        def done(path):
            self.model_path_var.set(path)
            self._save_settings_from_vars()
            size_text = _format_bytes(os.path.getsize(path)) if os.path.exists(path) else ""
            suffix = f" ({size_text})" if size_text else ""
            messagebox.showinfo("Update Model", f"Model download complete{suffix}.")

        def err(exc):
            messagebox.showerror("Update Model", str(exc))

        self._run_task(task, done, on_error=err, message="Updating model...", progress_label="Updating model")

    def _ensure_model_available(self, on_ready, on_skip):
        model_path = self.model_path_var.get().strip()
        if model_path and os.path.exists(model_path):
            on_ready()
            return

        wants_download = messagebox.askyesno(
            "Model missing",
            "The GGUF model is missing. Download the default model now?",
        )
        if not wants_download:
            on_skip()
            return

        def task(progress_cb=None):
            return self._download_default_model(progress_cb=progress_cb)

        def done(path):
            self.model_path_var.set(path)
            self._save_settings_from_vars()
            size_text = _format_bytes(os.path.getsize(path)) if os.path.exists(path) else ""
            suffix = f" ({size_text})" if size_text else ""
            if size_text:
                self.status_var.set(f"Download complete {size_text}")
            on_ready()

        def err(exc):
            messagebox.showerror("Download failed", str(exc))
            on_skip()

        self._run_task(task, done, on_error=err, message="Downloading model...", progress_label="Downloading model")

    def _get_llm(self):
        if Llama is None:
            raise RuntimeError("llama-cpp-python is not installed.")
        model_path = self.model_path_var.get().strip()
        if not model_path:
            raise RuntimeError("Model path is empty.")
        if not os.path.exists(model_path):
            raise RuntimeError("Model file not found.")
        if self.llm is not None and self.llm_path == model_path:
            return self.llm

        n_threads = max(2, os.cpu_count() or 2)
        n_gpu_layers = -1 if self.use_gpu_var.get() else 0
        self.llm = Llama(
            model_path=model_path,
            n_ctx=4096,
            n_threads=n_threads,
            n_gpu_layers=n_gpu_layers,
        )
        self.llm_path = model_path
        return self.llm

    def _reset_kb(self):
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            wants_backup = messagebox.askyesno(
                "Knowledge Base",
                "Would you like to back up the knowledge base before resetting?",
            )
            if wants_backup:
                if not self._backup_kb():
                    return

        confirm = messagebox.askyesno(
            "Knowledge Base",
            "Are you sure you want to reset the knowledge base?",
        )
        if not confirm:
            return

        if os.path.exists(KNOWLEDGE_BASE_FILE):
            os.remove(KNOWLEDGE_BASE_FILE)
        self._refresh_kb()
        messagebox.showinfo("Knowledge Base", "Knowledge base reset.")

    def _backup_kb(self):
        kb = load_knowledge_base()
        default_name = f"pcap_knowledge_base_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        initial_dir = self.backup_dir_var.get().strip() or os.path.dirname(KNOWLEDGE_BASE_FILE)
        path = filedialog.asksaveasfilename(
            title="Backup Knowledge Base",
            defaultextension=".json",
            initialfile=default_name,
            initialdir=initial_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(kb, f, indent=2)
        except Exception as exc:
            messagebox.showerror("Knowledge Base", f"Backup failed: {exc}")
            return False
        self.backup_dir_var.set(os.path.dirname(path))
        self._save_settings_from_vars()
        messagebox.showinfo("Knowledge Base", "Backup saved.")
        return True

    def _restore_kb(self):
        initial_dir = self.backup_dir_var.get().strip() or os.path.dirname(KNOWLEDGE_BASE_FILE)
        path = filedialog.askopenfilename(
            title="Restore Knowledge Base",
            initialdir=initial_dir,
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("Backup format is invalid.")
            data.setdefault("safe", [])
            data.setdefault("malicious", [])
            data.setdefault("ioc", {"ips": [], "domains": [], "hashes": []})
            save_knowledge_base(data)
        except Exception as exc:
            messagebox.showerror("Knowledge Base", f"Restore failed: {exc}")
            return
        self.backup_dir_var.set(os.path.dirname(path))
        self._save_settings_from_vars()
        self._refresh_kb()
        messagebox.showinfo("Knowledge Base", "Knowledge base restored.")

    def _load_ioc_file(self):
        path = self.ioc_path_var.get().strip()
        if not path:
            messagebox.showwarning("Missing file", "Please select an IoC file.")
            return
        if not os.path.exists(path):
            messagebox.showwarning("Missing file", "IoC file not found.")
            return

        def task():
            return load_iocs_from_file(path)

        def done(iocs):
            kb = load_knowledge_base()
            merge_iocs_into_kb(kb, iocs)
            save_knowledge_base(kb)
            self._refresh_kb()
            messagebox.showinfo("IoC Feed", "IoCs imported successfully.")

        self._run_task(task, done, message="Importing IoCs...")

    def _clear_iocs(self):
        kb = load_knowledge_base()
        kb["ioc"] = {"ips": [], "domains": [], "hashes": []}
        save_knowledge_base(kb)
        self._refresh_kb()
        messagebox.showinfo("IoC Feed", "IoCs cleared.")

    def _train(self, label):
        path = self.safe_path_var.get() if label == "safe" else self.mal_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP file.")
            return

        def task(progress_cb=None):
            return parse_pcap_path(
                path,
                max_rows=self.max_rows_var.get(),
                parse_http=self.parse_http_var.get(),
                progress_cb=progress_cb,
            )

        def done(result):
            df, stats, _ = result
            if stats.get("packet_count", 0) == 0:
                messagebox.showwarning("No data", "No IP packets found in this capture.")
                return
            features = build_features(stats)
            summary = summarize_stats(stats)
            add_to_knowledge_base(label, stats, features, summary)
            messagebox.showinfo("Training", f"Added {label} PCAP to knowledge base.")
            self._refresh_kb()

        self._run_task(task, done, message="Parsing PCAP...", progress_label="Parsing PCAP")

    def _label_current(self, label):
        if self.current_stats is None:
            messagebox.showwarning("Missing data", "Analyze a PCAP first.")
            return
        features = build_features(self.current_stats)
        summary = summarize_stats(self.current_stats)
        add_to_knowledge_base(label, self.current_stats, features, summary)
        self._refresh_kb()
        messagebox.showinfo("Knowledge Base", f"Current capture saved as {label}.")

    def _analyze(self):
        path = self.target_path_var.get()
        if not path:
            messagebox.showwarning("Missing file", "Please select a PCAP file.")
            return

        def task(progress_cb=None):
            return parse_pcap_path(
                path,
                max_rows=self.max_rows_var.get(),
                parse_http=self.parse_http_var.get(),
                progress_cb=progress_cb,
            )

        def done(result):
            df, stats, sample_info = result
            if stats.get("packet_count", 0) == 0:
                messagebox.showwarning("No data", "No IP packets found in this capture.")
                return

            self.current_df = df
            self.current_stats = stats
            self.current_sample_info = sample_info
            if self.label_safe_button is not None:
                self.label_safe_button.configure(state=tk.NORMAL)
            if self.label_mal_button is not None:
                self.label_mal_button.configure(state=tk.NORMAL)

            self.sample_note_var.set("")
            if sample_info["sample_count"] < sample_info["total_count"]:
                self.sample_note_var.set(
                    f"Charts use {sample_info['sample_count']} of {sample_info['total_count']} packets."
                )

            features = build_features(stats)
            vector = _vector_from_features(features)
            kb = load_knowledge_base()
            safe_scores = [similarity_score(features, e["features"]) for e in kb["safe"]]
            mal_scores = [similarity_score(features, e["features"]) for e in kb["malicious"]]

            baseline = compute_baseline_from_kb(kb)
            anomaly_result, anomaly_reasons = anomaly_score(vector, baseline)
            classifier_result = classify_vector(vector, kb)

            ioc_matches = match_iocs(stats, kb.get("ioc", {}))
            ioc_count = len(ioc_matches["ips"]) + len(ioc_matches["domains"])
            ioc_available = any(kb.get("ioc", {}).get(key) for key in ("ips", "domains", "hashes"))
            if ioc_count:
                ioc_score = min(100.0, 75.0 + (ioc_count - 1) * 5.0)
            else:
                ioc_score = 0.0

            risk_components = []
            if classifier_result is not None:
                risk_components.append((classifier_result["score"], 0.5))
            if anomaly_result is not None:
                risk_components.append((anomaly_result, 0.3))
            if ioc_available:
                risk_components.append((ioc_score, 0.2))

            if risk_components:
                total_weight = sum(weight for _, weight in risk_components)
                risk_score = sum(score * weight for score, weight in risk_components) / total_weight
                risk_score = round(risk_score, 1)
            else:
                risk_score = 0.0

            if risk_score >= 70:
                verdict = "Likely Malicious"
            elif risk_score >= 40:
                verdict = "Suspicious"
            else:
                verdict = "Likely Safe"
            if ioc_count and verdict == "Likely Safe":
                verdict = "Suspicious (IoC Match)"

            output_lines = [
                f"Risk Score: {risk_score}/100",
                f"Verdict: {verdict}",
                "",
                "Signals:",
            ]

            if classifier_result is None:
                output_lines.append("- Classifier: not enough labeled data")
            else:
                output_lines.append(f"- Classifier risk: {classifier_result['score']} (centroid distance)")

            if anomaly_result is None:
                output_lines.append("- Baseline anomaly: no safe baseline available")
            else:
                reasons = ", ".join(anomaly_reasons) if anomaly_reasons else "no standout outliers"
                output_lines.append(f"- Baseline anomaly: {anomaly_result} ({reasons})")

            if ioc_available:
                if ioc_count:
                    output_lines.append(
                        f"- IoC matches: {ioc_count} (domains: {len(ioc_matches['domains'])}, ips: {len(ioc_matches['ips'])})"
                    )
                    if ioc_matches["domains"]:
                        output_lines.append(f"  Domains: {', '.join(ioc_matches['domains'][:5])}")
                    if ioc_matches["ips"]:
                        output_lines.append(f"  IPs: {', '.join(ioc_matches['ips'][:5])}")
                else:
                    output_lines.append("- IoC matches: none")
            else:
                output_lines.append("- IoC feed: not loaded")

            if stats.get("ioc_truncated"):
                output_lines.append("- Note: IoC scan truncated due to large unique set")

            output_lines.append("")
            output_lines.append("Heuristic Similarity")
            output_lines.append(summarize_stats(stats))

            if not safe_scores and not mal_scores:
                output_lines.append("Knowledge base is empty. Add safe/malware PCAPs to enable scoring.")
            else:
                best_safe = max(safe_scores) if safe_scores else 0.0
                best_mal = max(mal_scores) if mal_scores else 0.0
                output_lines.append(f"Best safe match: {best_safe}")
                output_lines.append(f"Best malware match: {best_mal}")
                if best_mal - best_safe >= 10:
                    output_lines.append("Verdict: Likely Malicious")
                elif best_safe - best_mal >= 10:
                    output_lines.append("Verdict: Likely Safe")
                else:
                    output_lines.append("Verdict: Suspicious / Inconclusive")

            if self.use_llm_var.get():
                output_lines.append("\nLLM Verdict")
                output_lines.append("(running local model...)")

            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, "\n".join(output_lines))

            for row in self.flow_table.get_children():
                self.flow_table.delete(row)
            flow_df = compute_flow_stats(df)
            for _, row in flow_df.head(25).iterrows():
                self.flow_table.insert(
                    "",
                    tk.END,
                    values=(
                        row["Flow"],
                        int(row["Packets"]),
                        int(row["Bytes"]),
                        f"{row['Duration']:.2f}",
                    ),
                )

            self.charts_button.configure(state=tk.NORMAL)

            if self.use_llm_var.get():
                def run_llm():
                    self._run_task(
                        lambda: analyze_with_local_llm(stats, kb, self._get_llm()),
                        lambda response: self._append_llm_response(response),
                        message="Running local LLM...",
                    )

                def skip_llm():
                    self._append_llm_response("LLM analysis skipped.")

                self._ensure_model_available(run_llm, skip_llm)

        self._run_task(task, done, message="Analyzing PCAP...", progress_label="Analyzing PCAP")

    def _append_llm_response(self, response):
        if not response:
            response = "LLM analysis unavailable."
        self.result_text.insert(tk.END, f"\n{response}\n")

    def _open_charts(self):
        if self.current_df is None:
            return
        window = tk.Toplevel(self.root)
        window.title("PCAP Charts")
        window.geometry("1000x800")

        notebook = ttk.Notebook(window)
        notebook.pack(fill=tk.BOTH, expand=True)

        _add_chart_tab(notebook, "Timeline", _plot_scatter(self.current_df))
        _add_chart_tab(notebook, "Ports", _plot_port_hist(self.current_df))
        _add_chart_tab(notebook, "Protocols", _plot_proto_pie(self.current_df))
        _add_chart_tab(notebook, "DNS", _plot_top_dns(self.current_df))
        _add_chart_tab(notebook, "HTTP", _plot_top_http(self.current_df))
        _add_chart_tab(notebook, "Flows", _plot_top_flows(self.current_df))

    def _refresh_kb(self):
        kb = load_knowledge_base()
        self.kb_summary_var.set(f"Safe entries: {len(kb['safe'])} | Malware entries: {len(kb['malicious'])}")
        ioc = kb.get("ioc", {})
        ioc_counts = f"IoCs: {len(ioc.get('domains', []))} domains, {len(ioc.get('ips', []))} ips"
        self.ioc_summary_var.set(ioc_counts)
        self.kb_text.delete("1.0", tk.END)
        if kb["safe"] or kb["malicious"] or any(ioc.get(key) for key in ("domains", "ips", "hashes")):
            self.kb_text.insert(tk.END, json.dumps(kb, indent=2))
        else:
            self.kb_text.insert(tk.END, "Knowledge base is empty.")

    def _on_tab_changed(self, _event):
        self.sample_note_var.set("")


def main():
    if TkinterDnD is None:
        root = tk.Tk()
    else:
        root = TkinterDnD.Tk()
    app = PCAPSentryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
