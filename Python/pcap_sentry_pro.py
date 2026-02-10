import json
import os
import random
import statistics
import tempfile
from collections import Counter
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st
from scapy.all import DNS, DNSQR, IP, PcapReader, Raw, TCP, UDP

try:
    import ollama
except Exception:
    ollama = None

def _get_app_data_dir():
    base_dir = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.expanduser("~")
    data_dir = os.path.join(base_dir, "PCAP_Sentry")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


KNOWLEDGE_BASE_FILE = os.path.join(_get_app_data_dir(), "pcap_knowledge_base_offline.json")

st.set_page_config(page_title="Offline PCAP Sentry", layout="wide")

UPLOAD_CHUNK_SIZE = 4 * 1024 * 1024
SIZE_SAMPLE_LIMIT = 50000


def _default_kb():
    return {"safe": [], "malicious": []}


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
        return data
    except Exception:
        return _default_kb()


def save_knowledge_base(data):
    with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


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


def _write_upload_to_temp(uploaded_file):
    uploaded_file.seek(0)
    tfile = tempfile.NamedTemporaryFile(delete=False)
    try:
        while True:
            chunk = uploaded_file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            tfile.write(chunk)
    finally:
        tfile.close()
    return tfile.name


def _maybe_reservoir_append(items, item, limit, seen_count):
    if limit <= 0:
        return
    if len(items) < limit:
        items.append(item)
        return
    j = random.randint(1, seen_count)
    if j <= limit:
        items[j - 1] = item


def parse_pcap(uploaded_file, max_rows=200000, parse_http=True):
    tfile_path = _write_upload_to_temp(uploaded_file)
    rows = []
    size_samples = []
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
    }
    try:
        with PcapReader(tfile_path) as pcap:
            for pkt in pcap:
                if IP not in pkt:
                    continue
                stats["packet_count"] += 1
                pkt_size = len(pkt)
                stats["sum_size"] += pkt_size
                _maybe_reservoir_append(size_samples, pkt_size, SIZE_SAMPLE_LIMIT, stats["packet_count"])

                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
                stats["protocol_counts"][proto] += 1

                sport = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else 0
                dport = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else 0
                if dport:
                    stats["port_counts"][dport] += 1

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                stats["unique_src"].add(src_ip)
                stats["unique_dst"].add(dst_ip)

                dns_query = ""
                if DNS in pkt:
                    try:
                        qd = pkt[DNS].qd
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
                    stats["dns_counter"][dns_query] += 1

                http_host = ""
                http_path = ""
                http_method = ""
                if parse_http and TCP in pkt and Raw in pkt:
                    http_host, http_path, http_method = parse_http_payload(bytes(pkt[Raw].load))
                if http_host:
                    stats["http_request_count"] += 1
                    stats["unique_http_hosts"].add(http_host)

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
                _maybe_reservoir_append(rows, row, max_rows, stats["packet_count"])
    finally:
        os.unlink(tfile_path)

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
    }
    sample_info = {
        "sample_count": len(rows),
        "total_count": packet_count,
    }
    return pd.DataFrame(rows), final_stats, sample_info


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
        return host, path, method
    except Exception:
        return "", "", ""


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


def analyze_with_llm(stats, kb):
    if ollama is None:
        return None
    prompt = (
        "You are an offline malware analyst. Compare the target PCAP stats to known safe and "
        "malicious patterns and provide a short verdict with reasoning.\n"
        f"Known safe summaries: {[e['summary'] for e in kb['safe']]}\n"
        f"Known malicious summaries: {[e['summary'] for e in kb['malicious']]}\n"
        f"Target stats: {summarize_stats(stats)}\n"
        "Return: verdict (Safe/Malicious/Suspicious) and 2-4 bullet points."
    )
    response = ollama.generate(model="llama3", prompt=prompt)
    return response.get("response", "")


def compute_flow_stats(df):
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


def render_visuals(df):
    st.subheader("Traffic Visualization")
    col_v1, col_v2 = st.columns(2)

    with col_v1:
        st.write("Packet Volume (Timeline)")
        fig_time = px.scatter(df, x="Time", y="Size", color="Proto", title="Traffic Spikes")
        st.plotly_chart(fig_time, use_container_width=True)

    with col_v2:
        st.write("Port Distribution")
        fig_port = px.histogram(df, x="DPort", color="Proto", title="Common Destination Ports")
        st.plotly_chart(fig_port, use_container_width=True)

    st.write("Protocol Mix")
    fig_proto = px.pie(df, names="Proto", title="Protocol Share")
    st.plotly_chart(fig_proto, use_container_width=True)

    dns_queries = [q for q in df["DnsQuery"] if q]
    if dns_queries:
        st.write("Top DNS Queries")
        dns_df = pd.DataFrame(Counter(dns_queries).most_common(10), columns=["Query", "Count"])
        fig_dns = px.bar(dns_df, x="Query", y="Count", title="DNS Query Frequency")
        st.plotly_chart(fig_dns, use_container_width=True)

    http_hosts = [h for h in df["HttpHost"] if h]
    if http_hosts:
        st.write("Top HTTP Hosts")
        http_df = pd.DataFrame(Counter(http_hosts).most_common(10), columns=["Host", "Count"])
        fig_http = px.bar(http_df, x="Host", y="Count", title="HTTP Host Frequency")
        st.plotly_chart(fig_http, use_container_width=True)

    flow_df = compute_flow_stats(df)
    if not flow_df.empty:
        st.write("Top Flows by Bytes")
        fig_flow = px.bar(flow_df.head(10), x="Flow", y="Bytes", title="Flow Volume")
        st.plotly_chart(fig_flow, use_container_width=True)


st.title("PCAP Sentry (Offline)")

with st.sidebar:
    st.header("Offline Model")
    if ollama is None:
        st.status("Ollama not available", state="error")
    else:
        st.status("Ollama available", state="complete")
    use_llm = st.checkbox("Use local LLM (Ollama)", value=ollama is not None)

    st.divider()
    st.subheader("Performance")
    max_packets = st.slider("Max packets for visuals", 10000, 500000, 200000, step=10000)
    parse_http = st.checkbox("Parse HTTP payloads", value=True)

    if st.button("Reset Knowledge Base"):
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            os.remove(KNOWLEDGE_BASE_FILE)
        st.rerun()

train_tab, analyze_tab, kb_tab = st.tabs(["Train", "Analyze", "Knowledge Base"])

with train_tab:
    st.subheader("Train Offline Knowledge")
    col_safe, col_mal = st.columns(2)

    with col_safe:
        safe_file = st.file_uploader("Upload Known Safe PCAP", type=["pcap"], key="safe")
        if safe_file and st.button("Add to Safe", key="safe_btn"):
            df, stats, sample_info = parse_pcap(safe_file, max_rows=max_packets, parse_http=parse_http)
            if stats.get("packet_count", 0) == 0:
                st.warning("No IP packets found in this capture.")
            else:
                features = build_features(stats)
                summary = summarize_stats(stats)
                add_to_knowledge_base("safe", stats, features, summary)
                st.success("Safe PCAP added to knowledge base.")

    with col_mal:
        mal_file = st.file_uploader("Upload Known Malware PCAP", type=["pcap"], key="mal")
        if mal_file and st.button("Add to Malware", key="mal_btn"):
            df, stats, sample_info = parse_pcap(mal_file, max_rows=max_packets, parse_http=parse_http)
            if stats.get("packet_count", 0) == 0:
                st.warning("No IP packets found in this capture.")
            else:
                features = build_features(stats)
                summary = summarize_stats(stats)
                add_to_knowledge_base("malicious", stats, features, summary)
                st.error("Malware PCAP added to knowledge base.")

with analyze_tab:
    st.subheader("Evaluate Target PCAP")
    target_file = st.file_uploader("Upload Target PCAP", type=["pcap"], key="target")

    if target_file:
        df, stats, sample_info = parse_pcap(target_file, max_rows=max_packets, parse_http=parse_http)
        if stats.get("packet_count", 0) == 0:
            st.warning("No IP packets found in this capture.")
        else:
            if sample_info["sample_count"] < sample_info["total_count"]:
                st.info(
                    f"Visuals use a sampled {sample_info['sample_count']} packets "
                    f"from {sample_info['total_count']} total for speed."
                )
            features = build_features(stats)
            render_visuals(df)

            flow_df = compute_flow_stats(df)
            if not flow_df.empty:
                st.subheader("Flow Summary")
                st.dataframe(flow_df.head(25), use_container_width=True)

            kb = load_knowledge_base()
            safe_scores = [similarity_score(features, e["features"]) for e in kb["safe"]]
            mal_scores = [similarity_score(features, e["features"]) for e in kb["malicious"]]

            st.subheader("Heuristic Verdict")
            if not safe_scores and not mal_scores:
                st.info("Knowledge base is empty. Add safe/malware PCAPs to enable scoring.")
            else:
                best_safe = max(safe_scores) if safe_scores else 0.0
                best_mal = max(mal_scores) if mal_scores else 0.0
                st.write(f"Best safe match: {best_safe}")
                st.write(f"Best malware match: {best_mal}")

                if best_mal - best_safe >= 10:
                    st.error("Verdict: Likely Malicious")
                elif best_safe - best_mal >= 10:
                    st.success("Verdict: Likely Safe")
                else:
                    st.warning("Verdict: Suspicious / Inconclusive")

            if use_llm and ollama is not None:
                st.subheader("LLM Verdict")
                with st.spinner("Analyzing with local LLM..."):
                    llm_response = analyze_with_llm(stats, kb)
                if llm_response:
                    st.info(llm_response)
                else:
                    st.warning("LLM analysis unavailable.")

with kb_tab:
    st.subheader("Stored Knowledge")
    kb = load_knowledge_base()
    st.write(f"Safe entries: {len(kb['safe'])}")
    st.write(f"Malware entries: {len(kb['malicious'])}")
    if kb["safe"] or kb["malicious"]:
        st.json(kb)
