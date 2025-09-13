#!/usr/bin/env python3
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
import os
import sys
import socket

if len(sys.argv) < 2:
    print("Usage: python3 script.py <pcapfile>")
    exit(1)

pcap_file = sys.argv[1]
if not os.path.exists(pcap_file):
    print(f"File not found: {pcap_file}")
    exit(1)

packets = rdpcap(pcap_file)

# --- Organize flows --- (key: (src_ip,dst_ip,src_port,dst_port,proto))
flows = defaultdict(list)
for pkt in packets:
    if IP in pkt:
        proto = pkt[IP].proto
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        else:
            src_port = 0
            dst_port = 0
        key = (src_ip, dst_ip, src_port, dst_port, int(proto))
        flows[key].append(pkt)

def compute_iat(times):
    if len(times) < 2:
        return np.array([0.0])
    iat = np.diff(np.sort(times))
    return iat

rows = []
# iterate flows and compute approximate features we can derive
for (src_ip, dst_ip, src_port, dst_port, proto), pkts in flows.items():
    times = np.array([float(p.time) for p in pkts])
    lengths = np.array([int(len(p)) for p in pkts])
    duration = float(times.max() - times.min()) if times.size > 0 else 0.0

    # forward = packets where IP.src == src_ip; backward = from dst->src
    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]
    fwd_lengths = np.array([int(len(p)) for p in fwd_pkts]) if fwd_pkts else np.array([], dtype=int)
    bwd_lengths = np.array([int(len(p)) for p in bwd_pkts]) if bwd_pkts else np.array([], dtype=int)

    fwd_iat = compute_iat(np.array([float(p.time) for p in fwd_pkts])) if fwd_pkts else np.array([0.0])
    bwd_iat = compute_iat(np.array([float(p.time) for p in bwd_pkts])) if bwd_pkts else np.array([0.0])

    # TTLs (mean per direction)
    fwd_ttls = [int(p[IP].ttl) for p in fwd_pkts if IP in p]
    bwd_ttls = [int(p[IP].ttl) for p in bwd_pkts if IP in p]
    sttl_mean = float(np.mean(fwd_ttls)) if fwd_ttls else 0.0
    dttl_mean = float(np.mean(bwd_ttls)) if bwd_ttls else 0.0

    # window sizes (mean)
    swin_val = float(np.mean([int(p[TCP].window) for p in fwd_pkts if TCP in p])) if any(TCP in p for p in fwd_pkts) else 0.0
    dwin_val = float(np.mean([int(p[TCP].window) for p in bwd_pkts if TCP in p])) if any(TCP in p for p in bwd_pkts) else 0.0

    # flags counts and SYN-ACK count
    synack_count = 0
    ack_count = 0
    syn_count = 0
    for p in pkts:
        if TCP in p:
            flags_str = str(p[TCP].flags)
            if 'S' in flags_str:
                syn_count += 1
            if 'A' in flags_str:
                ack_count += 1
            # detect SYN+ACK combo
            if ('S' in flags_str) and ('A' in flags_str):
                synack_count += 1

    # approximate service name by destination port & proto
    proto_name = 'tcp' if proto == 6 else ('udp' if proto == 17 else 'other')
    service_name = ""
    try:
        # socket expects port and 'tcp'/'udp'
        if dst_port and proto_name in ('tcp','udp'):
            service_name = socket.getservbyport(dst_port, proto_name)
    except Exception:
        service_name = ""

    # detect simple FTP login (USER/PASS) and count ftp/http commands in payloads
    is_ftp_login = 0
    ct_ftp_cmd = 0
    ct_flw_http_mthd = 0
    http_methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "]
    ftp_cmds = [b"USER", b"PASS", b"230 ", b"331 "]

    for p in pkts:
        payload = b""
        # try to get TCP/UDP payload bytes safely
        if TCP in p:
            try:
                payload = bytes(p[TCP].payload)
            except Exception:
                payload = b""
        elif UDP in p:
            try:
                payload = bytes(p[UDP].payload)
            except Exception:
                payload = b""

        if any(cmd in payload for cmd in ftp_cmds):
            ct_ftp_cmd += 1
        if any(m in payload for m in http_methods):
            ct_flw_http_mthd += 1
        if (b"USER " in payload) or (b"PASS " in payload):
            is_ftp_login = 1

    # build the row with all original metrics we need for mapping
    row = {
        # base raw values kept for mapping
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "proto_num": int(proto),
        "service": service_name,
        "duration": duration,
        "spkts": int(len(fwd_lengths)),
        "dpkts": int(len(bwd_lengths)),
        "sbytes": int(fwd_lengths.sum()) if fwd_lengths.size>0 else 0,
        "dbytes": int(bwd_lengths.sum()) if bwd_lengths.size>0 else 0,
        "rate": float(lengths.sum()/duration) if duration > 0 else 0.0,
        "sttl": sttl_mean,
        "dttl": dttl_mean,
        "sload": float((fwd_lengths.sum()/duration)) if duration>0 else 0.0,
        "dload": float((bwd_lengths.sum()/duration)) if duration>0 else 0.0,
        "sloss": 0,     # not derivable from single pcap reliably -> default 0
        "dloss": 0,     # same as above
        "sinpkt": int(len(fwd_lengths)),  # same as spkts
        "dinpkt": int(len(bwd_lengths)),  # same as dpkts
        "sjit": float(fwd_iat.std()) if fwd_iat.size>0 else 0.0,
        "djit": float(bwd_iat.std()) if bwd_iat.size>0 else 0.0,
        "swin": float(swin_val),
        "stcpb": float(np.mean(fwd_lengths)) if fwd_lengths.size>0 else 0.0,  # avg forward seg size
        "dtcpb": float(np.mean(bwd_lengths)) if bwd_lengths.size>0 else 0.0,  # avg backward seg size
        "dwin": float(dwin_val),
        "tcprtt": 0.0,  # not reliably derivable here -> default 0
        "synack": int(synack_count),
        "ackdat": int(ack_count),
        "smean": float(np.mean(fwd_lengths)) if fwd_lengths.size>0 else 0.0,
        "dmean": float(np.mean(bwd_lengths)) if bwd_lengths.size>0 else 0.0,
        "trans_depth": float(np.mean([len(fwd_lengths[i:i+10]) for i in range(0, len(fwd_lengths), 10)])) if fwd_lengths.size>0 else 0.0,
        "response_body_len": 0,  # requires application parsing -> default 0
        # simple counts we can compute later
        "ct_ftp_cmd": int(ct_ftp_cmd),
        "ct_flw_http_mthd": int(ct_flw_http_mthd),
        "is_ftp_login": int(is_ftp_login),
    }
    rows.append(row)

# --- compute ct_* aggregated counts across flows (long-term counts) ---
count_dst = Counter([r["dst_ip"] for r in rows])
count_src = Counter([r["src_ip"] for r in rows])
count_src_dport = Counter([(r["src_ip"], r["dst_port"]) for r in rows])
count_dst_sport = Counter([(r["dst_ip"], r["src_port"]) for r in rows])
count_dst_src = Counter([(r["dst_ip"], r["src_ip"]) for r in rows])
count_srv_src = Counter([(r["service"], r["src_ip"]) for r in rows])
count_srv_dst = Counter([(r["service"], r["dst_ip"]) for r in rows])

# Build final filtered rows with EXACT column names requested
final_rows = []
for r in rows:
    src_ip = r["src_ip"]
    dst_ip = r["dst_ip"]
    src_port = r["src_port"]
    dst_port = r["dst_port"]
    service = r["service"]

    final = {
        "dur": r["duration"],
        "proto": r["proto_num"],            # protocol number (e.g., 6 for TCP)
        "service": service,
        "state": "",                        # not derivable reliably from pcap alone -> left empty
        "spkts": r["spkts"],
        "dpkts": r["dpkts"],
        "sbytes": r["sbytes"],
        "dbytes": r["dbytes"],
        "rate": r["rate"],
        "sttl": r["sttl"],
        "dttl": r["dttl"],
        "sload": r["sload"],
        "dload": r["dload"],
        "sloss": r["sloss"],
        "dloss": r["dloss"],
        "sinpkt": r["sinpkt"],
        "dinpkt": r["dinpkt"],
        "sjit": r["sjit"],
        "djit": r["djit"],
        "swin": r["swin"],
        "stcpb": r["stcpb"],
        "dtcpb": r["dtcpb"],
        "dwin": r["dwin"],
        "tcprtt": r["tcprtt"],
        "synack": r["synack"],
        "ackdat": r["ackdat"],
        "smean": r["smean"],
        "dmean": r["dmean"],
        "trans_depth": r["trans_depth"],
        "response_body_len": r["response_body_len"],
        # aggregated counts (long-term / cross-flow)
        "ct_srv_src": count_srv_src[(service, src_ip)],
        "ct_state_ttl": 0,  # not available directly -> default 0
        "ct_dst_ltm": count_dst[dst_ip],
        "ct_src_dport_ltm": count_src_dport[(src_ip, dst_port)],
        "ct_dst_sport_ltm": count_dst_sport[(dst_ip, src_port)],
        "ct_dst_src_ltm": count_dst_src[(dst_ip, src_ip)],
        "is_ftp_login": r["is_ftp_login"],
        "ct_ftp_cmd": r["ct_ftp_cmd"],
        "ct_flw_http_mthd": r["ct_flw_http_mthd"],
        "ct_src_ltm": count_src[src_ip],
        "ct_srv_dst": count_srv_dst[(service, dst_ip)],
        "is_sm_ips_ports": 0  # requires dataset-level heuristics -> default 0
    }
    final_rows.append(final)

# Create DataFrame with exactly the requested columns in the order provided
columns = [
    "dur","proto","service","state","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl",
    "sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit","swin","stcpb","dtcpb",
    "dwin","tcprtt","synack","ackdat","smean","dmean","trans_depth","response_body_len",
    "ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm",
    "ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst",
    "is_sm_ips_ports"
]

df_filtered = pd.DataFrame(final_rows, columns=columns)
out_path = "filtered_data.csv"
df_filtered.to_csv(out_path, index=False)
print(f"Filtered data saved to {out_path} with {len(df_filtered)} rows and {len(columns)} columns.")
