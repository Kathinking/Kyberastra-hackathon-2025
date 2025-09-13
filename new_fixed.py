import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import os
import sys
from datetime import datetime

if len(sys.argv) < 2:
    print("Usage: python extract_unsw_columns.py <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]
if not os.path.exists(pcap_file):
    print(f"File not found: {pcap_file}")
    exit(1)

packets = rdpcap(pcap_file)

# --- Organize flows ---
# Key: (src_ip, dst_ip, src_port, dst_port, proto)
flows = defaultdict(list)

for pkt in packets:
    if IP in pkt:
        proto = pkt[IP].proto
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            src_port = 0
            dst_port = 0
        key = (src_ip, dst_ip, int(src_port), int(dst_port), int(proto))
        flows[key].append(pkt)

# helper
def compute_iat(times):
    if len(times) < 2:
        return np.array([0.0])
    iat = np.diff(np.sort(times))
    return iat

# map common ports to service names (simple)
port_service_map = {
    80: "http", 21: "ftp", 20: "ftp-data", 25: "smtp", 22: "ssh", 53: "dns", 6667: "irc"
}

rows = []
# First pass: compute per-flow basic features
for (src_ip, dst_ip, src_port, dst_port, proto), pkts in flows.items():
    times = np.array([float(p.time) for p in pkts])
    if times.size == 0:
        continue
    lengths = np.array([len(p) for p in pkts])

    # Directional split based on IP.src
    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]
    fwd_lengths = np.array([len(p) for p in fwd_pkts]) if len(fwd_pkts)>0 else np.array([])
    bwd_lengths = np.array([len(p) for p in bwd_pkts]) if len(bwd_pkts)>0 else np.array([])

    flow_iat = compute_iat(times)
    fwd_iat = compute_iat(np.array([float(p.time) for p in fwd_pkts])) if len(fwd_pkts)>0 else np.array([0.0])
    bwd_iat = compute_iat(np.array([float(p.time) for p in bwd_pkts])) if len(bwd_pkts)>0 else np.array([0.0])

    duration = float(times.max() - times.min()) if times.max() - times.min() > 0 else 0.0

    # TTLs: pick first packet's ttl per direction
    sttl = 0
    dttl = 0
    for p in fwd_pkts:
        if IP in p:
            sttl = int(p[IP].ttl)
            break
    for p in bwd_pkts:
        if IP in p:
            dttl = int(p[IP].ttl)
            break

    # TCP flag counts
    flags = ['F','S','R','P','A','U','C','E']
    flag_counts = dict.fromkeys(flags, 0)
    for p in pkts:
        if TCP in p:
            f = str(p[TCP].flags)
            for ch in flags:
                if ch in f:
                    flag_counts[ch] += 1

    # Retransmission (approx): duplicate seq numbers per direction
    def count_dup_seqs(pkt_list):
        seqs = []
        for p in pkt_list:
            if TCP in p:
                try:
                    seqs.append(int(p[TCP].seq))
                except:
                    pass
        if not seqs:
            return 0
        unique = set()
        dups = 0
        for s in seqs:
            if s in unique:
                dups += 1
            else:
                unique.add(s)
        return int(dups)
    sloss = count_dup_seqs(fwd_pkts)
    dloss = count_dup_seqs(bwd_pkts)

    # service detection by dst port (simple)
    svc = port_service_map.get(int(dst_port), "-")

    # bits/sec for source / dest
    sbytes = int(fwd_lengths.sum()) if fwd_lengths.size>0 else 0
    dbytes = int(bwd_lengths.sum()) if bwd_lengths.size>0 else 0
    Sload = (sbytes * 8 / duration) if duration>0 else 0.0
    Dload = (dbytes * 8 / duration) if duration>0 else 0.0

    Spkts = int(len(fwd_lengths))
    Dpkts = int(len(bwd_lengths))

    swin = float(np.mean([p[TCP].window for p in fwd_pkts if TCP in p])) if any(TCP in p for p in fwd_pkts) else 0.0
    dwin = float(np.mean([p[TCP].window for p in bwd_pkts if TCP in p])) if any(TCP in p for p in bwd_pkts) else 0.0

    # base seq numbers (first seen in each dir)
    stcpb = 0
    dtcpb = 0
    for p in fwd_pkts:
        if TCP in p:
            try:
                stcpb = int(p[TCP].seq)
            except:
                pass
            break
    for p in bwd_pkts:
        if TCP in p:
            try:
                dtcpb = int(p[TCP].seq)
            except:
                pass
            break

    smeansz = float(fwd_lengths.mean()) if fwd_lengths.size>0 else 0.0
    dmeansz = float(bwd_lengths.mean()) if bwd_lengths.size>0 else 0.0

    # HTTP methods count & trans_depth approx
    trans_depth = 0
    ct_flw_http_mthd = 0
    http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS']
    for p in pkts:
        raw = bytes(p.payload)
        for m in http_methods:
            ct_flw_http_mthd += raw.count(m)
    trans_depth = int(ct_flw_http_mthd)  # approximate pipeline depth by number of methods

    # response body len (approx): if service http, assume server->client is bwd; sum bwd_lengths
    res_bdy_len = int(bwd_lengths.sum()) if svc == "http" else 0

    # jitter approximations (std of IAT)
    Sjit = float(np.std(fwd_iat)) if fwd_iat.size>0 else 0.0
    Djit = float(np.std(bwd_iat)) if bwd_iat.size>0 else 0.0

    # Stime, Ltime (timestamps)
    Stime = float(times.min())
    Ltime = float(times.max())

    Sintpkt = float(fwd_iat.mean()) if fwd_iat.size>0 else 0.0
    Dintpkt = float(bwd_iat.mean()) if bwd_iat.size>0 else 0.0

    # TCP handshake times (approx)
    syn_t = None
    synack_t = None
    ack_t = None
    for p in pkts:
        if TCP in p:
            flags_s = str(p[TCP].flags)
            t = float(p.time)
            # SYN from source
            if ('S' in flags_s) and ('A' not in flags_s) and p[IP].src == src_ip and syn_t is None:
                syn_t = t
            # SYN-ACK from destination (has S and A)
            if ('S' in flags_s) and ('A' in flags_s) and p[IP].src == dst_ip and synack_t is None:
                synack_t = t
            # ACK from source after synack
            if ('A' in flags_s) and p[IP].src == src_ip and synack_t is not None and t >= synack_t and ack_t is None:
                ack_t = t
    synack = float(synack_t - syn_t) if syn_t is not None and synack_t is not None else 0.0
    ackdat = float(ack_t - synack_t) if synack_t is not None and ack_t is not None else 0.0
    tcprtt = float(synack + ackdat) if (synack and ackdat) else float(synack if synack else 0.0)

    # is_sm_ips_ports
    is_sm_ips_ports = 1 if (src_ip == dst_ip and int(src_port) == int(dst_port)) else 0

    # ct_state_ttl: approximate TTL-range bucket for source TTL
    if sttl < 32:
        ct_state_ttl = 1
    elif sttl < 64:
        ct_state_ttl = 2
    elif sttl < 128:
        ct_state_ttl = 3
    else:
        ct_state_ttl = 4

    # FTP login detection
    ftp_commands = [b'USER', b'PASS', b'RETR', b'STOR', b'LIST']
    ct_ftp_cmd = 0
    seen_user = False
    seen_pass = False
    for p in pkts:
        raw = bytes(p.payload)
        for c in ftp_commands:
            cnt = raw.count(c)
            if cnt > 0:
                ct_ftp_cmd += cnt
            if c == b'USER' and cnt>0:
                seen_user = True
            if c == b'PASS' and cnt>0:
                seen_pass = True
    is_ftp_login = 1 if (seen_user and seen_pass) else 0

    # Build row with requested field names (UNSW order)
    row = {
        "srcip": src_ip,
        "sport": int(src_port),
        "dstip": dst_ip,
        "dsport": int(dst_port),
        "proto": "tcp" if int(proto)==6 else ("udp" if int(proto)==17 else str(int(proto))),
        "state": str("SYN" if flag_counts['S']>0 and flag_counts['A']==0 else ("ESTAB" if flag_counts['A']>0 else "-")),
        "dur": float(duration),
        "sbytes": int(sbytes),
        "dbytes": int(dbytes),
        "sttl": int(sttl),
        "dttl": int(dttl),
        "sloss": int(sloss),
        "dloss": int(dloss),
        "service": svc,
        "Sload": float(Sload),
        "Dload": float(Dload),
        "Spkts": int(Spkts),
        "Dpkts": int(Dpkts),
        "swin": float(swin),
        "dwin": float(dwin),
        "stcpb": int(stcpb),
        "dtcpb": int(dtcpb),
        "smeansz": float(smeansz),
        "dmeansz": float(dmeansz),
        "trans_depth": int(trans_depth),
        "res_bdy_len": int(res_bdy_len),
        "Sjit": float(Sjit),
        "Djit": float(Djit),
        "Stime": float(Stime),
        "Ltime": float(Ltime),
        "Sintpkt": float(Sintpkt),
        "Dintpkt": float(Dintpkt),
        "tcprtt": float(tcprtt),
        "synack": float(synack),
        "ackdat": float(ackdat),
        "is_sm_ips_ports": int(is_sm_ips_ports),
        "ct_state_ttl": int(ct_state_ttl),
        "ct_flw_http_mthd": int(ct_flw_http_mthd),
        "is_ftp_login": int(is_ftp_login),
        "ct_ftp_cmd": int(ct_ftp_cmd),
        # placeholders for ct_* that require looking at nearby flows; fill later
        "ct_srv_src": 0,
        "ct_srv_dst": 0,
        "ct_dst_ltm": 0,
        "ct_src_ltm": 0,
        "ct_src_dport_ltm": 0,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 0,
        "attack_cat": "",
        "Label": ""
    }

    rows.append(row)

# --- Second pass: compute the ct_* fields by looking at previous 100 connections sorted by Stime ---
df = pd.DataFrame(rows)
if df.empty:
    print("No flows found.")
    sys.exit(0)

# sort by Stime to emulate "last time" ordering
df = df.sort_values(by="Stime").reset_index(drop=True)

for i, r in df.iterrows():
    window_start = max(0, i - 100)
    window = df.iloc[window_start:i]  # previous 100 only (not including current)
    # ct_srv_src: same service and source address in previous 100 connections
    df.at[i, "ct_srv_src"] = int(((window["service"] == r["service"]) & (window["srcip"] == r["srcip"])).sum())
    # ct_srv_dst: same service and destination address
    df.at[i, "ct_srv_dst"] = int(((window["service"] == r["service"]) & (window["dstip"] == r["dstip"])).sum())
    # ct_dst_ltm: connections with same destination address
    df.at[i, "ct_dst_ltm"] = int((window["dstip"] == r["dstip"]).sum())
    # ct_src_ltm: connections with same source address
    df.at[i, "ct_src_ltm"] = int((window["srcip"] == r["srcip"]).sum())
    # ct_src_dport_ltm: same source and destination port
    df.at[i, "ct_src_dport_ltm"] = int(((window["srcip"] == r["srcip"]) & (window["dsport"] == r["dsport"])).sum())
    # ct_dst_sport_ltm: same destination and source port
    df.at[i, "ct_dst_sport_ltm"] = int(((window["dstip"] == r["dstip"]) & (window["sport"] == r["sport"])).sum())
    # ct_dst_src_ltm: same source and destination pair
    df.at[i, "ct_dst_src_ltm"] = int(((window["srcip"] == r["srcip"]) & (window["dstip"] == r["dstip"])).sum())

# Reorder columns exactly as you listed (49 columns)
cols_order = [
    "srcip","sport","dstip","dsport","proto","state","dur","sbytes","dbytes","sttl","dttl","sloss","dloss",
    "service","Sload","Dload","Spkts","Dpkts","swin","dwin","stcpb","dtcpb","smeansz","dmeansz","trans_depth",
    "res_bdy_len","Sjit","Djit","Stime","Ltime","Sintpkt","Dintpkt","tcprtt","synack","ackdat","is_sm_ips_ports",
    "ct_state_ttl","ct_flw_http_mthd","is_ftp_login","ct_ftp_cmd","ct_srv_src","ct_srv_dst","ct_dst_ltm",
    "ct_src_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","attack_cat","Label"
]

# Some defensive checks: ensure all cols in df
for c in cols_order:
    if c not in df.columns:
        df[c] = ""

df = df[cols_order]

# Save CSV
out_file = "unsw_features.csv"
df.to_csv(out_file, index=False)
print(f"Wrote {len(df)} flows with {len(cols_order)} UNSW-like columns to {out_file}")
