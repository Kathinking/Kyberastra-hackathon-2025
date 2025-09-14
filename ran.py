import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import os
import sys

# --- Load PCAP ---
if len(sys.argv) < 2:
    print("Usage: python script.py <pcap_file>")
    exit(1)

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
            # For other IP protocols like ICMP
            src_port = 0
            dst_port = 0
        
        # To keep flows bidirectional, we normalize the key
        # The lower IP:port is always first
        if (src_ip, src_port) < (dst_ip, dst_port):
            key = (src_ip, dst_ip, src_port, dst_port, proto)
        else:
            key = (dst_ip, src_ip, dst_port, src_port, proto)
        
        flows[key].append(pkt)

# --- Feature extraction ---
def compute_iat(times):
    if len(times) < 2:
        return np.array([0])
    # Ensure times are sorted before diff
    iat = np.diff(sorted(times))
    return iat

rows = []

for key, pkts in flows.items():
    # The first packet determines the forward direction
    flow_start_pkt = pkts[0]
    src_ip, dst_ip, src_port, dst_port, proto = (
        flow_start_pkt[IP].src, 
        flow_start_pkt[IP].dst,
        flow_start_pkt[TCP].sport if TCP in flow_start_pkt else (flow_start_pkt[UDP].sport if UDP in flow_start_pkt else 0),
        flow_start_pkt[TCP].dport if TCP in flow_start_pkt else (flow_start_pkt[UDP].dport if UDP in flow_start_pkt else 0),
        flow_start_pkt[IP].proto
    )
    
    times = np.array([p.time for p in pkts]).astype(float)
    lengths = np.array([len(p) for p in pkts])

    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]

    fwd_lengths = np.array([len(p) for p in fwd_pkts]) if fwd_pkts else np.array([0])
    bwd_lengths = np.array([len(p) for p in bwd_pkts]) if bwd_pkts else np.array([0])
    
    fwd_times = np.array([p.time for p in fwd_pkts]).astype(float) if fwd_pkts else np.array([0])
    bwd_times = np.array([p.time for p in bwd_pkts]).astype(float) if bwd_pkts else np.array([0])

    flow_iat = compute_iat(times)
    fwd_iat = compute_iat(fwd_times)
    bwd_iat = compute_iat(bwd_times)
    
    flow_duration = max(times) - min(times) if len(times) > 1 else 0

    # TCP Flags
    flags = ['F', 'S', 'R', 'P', 'A', 'U', 'C', 'E']  # FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
    flag_counts = {f: 0 for f in flags}
    fwd_psh_flags = 0
    bwd_psh_flags = 0
    fwd_urg_flags = 0
    bwd_urg_flags = 0

    for p in pkts:
        if TCP in p:
            for f_char in p[TCP].flags.flagrepr():
                if f_char in flag_counts:
                    flag_counts[f_char] += 1
            # Directional flags
            if p[IP].src == src_ip:
                if 'P' in p[TCP].flags: fwd_psh_flags += 1
                if 'U' in p[TCP].flags: fwd_urg_flags += 1
            else:
                if 'P' in p[TCP].flags: bwd_psh_flags += 1
                if 'U' in p[TCP].flags: bwd_urg_flags += 1

    # Down/Up ratio
    down_up_ratio = (len(bwd_pkts) / len(fwd_pkts)) if len(fwd_pkts) > 0 else 0
    
    # Fwd/Bwd Header Length
    fwd_header_len_total = sum(p[IP].ihl * 4 + (p[TCP].dataofs * 4 if TCP in p else 8) for p in fwd_pkts)
    bwd_header_len_total = sum(p[IP].ihl * 4 + (p[TCP].dataofs * 4 if TCP in p else 8) for p in bwd_pkts)

    # Subflow (approximated)
    subflow_size = 10
    subflow_fwd_pkts_list = [len(fwd_lengths[i:i+subflow_size]) for i in range(0, len(fwd_lengths), subflow_size)]
    subflow_fwd_bytes_list = [sum(fwd_lengths[i:i+subflow_size]) for i in range(0, len(fwd_lengths), subflow_size)]
    subflow_bwd_pkts_list = [len(bwd_lengths[i:i+subflow_size]) for i in range(0, len(bwd_lengths), subflow_size)]
    subflow_bwd_bytes_list = [sum(bwd_lengths[i:i+subflow_size]) for i in range(0, len(bwd_lengths), subflow_size)]

    # Active/Idle times
    sorted_times = np.sort(times)
    inter_arrival_times = np.diff(sorted_times)
    idle_threshold = 1_000_000  # 1 second in microseconds from epoch time
    idle_periods = inter_arrival_times[inter_arrival_times > idle_threshold]
    active_periods = inter_arrival_times[inter_arrival_times <= idle_threshold]

    # Initial Window Bytes
    init_fwd_win_bytes = fwd_pkts[0][TCP].window if fwd_pkts and TCP in fwd_pkts[0] else 0
    init_bwd_win_bytes = bwd_pkts[0][TCP].window if bwd_pkts and TCP in bwd_pkts[0] else 0
    
    # Active data packets forward
    act_data_pkt_fwd = sum(1 for p in fwd_pkts if (TCP in p and len(p[TCP].payload) > 0) or (UDP in p and len(p[UDP].payload) > 0))

    row = {
        "Protocol": proto,
        "Flow Duration": flow_duration,
        "Total Fwd Packets": len(fwd_pkts),
        "Total Backward Packets": len(bwd_pkts),
        "Fwd Packets Length Total": sum(fwd_lengths),
        "Bwd Packets Length Total": sum(bwd_lengths),
        "Fwd Packet Length Max": max(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Fwd Packet Length Min": min(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Fwd Packet Length Mean": np.mean(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Fwd Packet Length Std": np.std(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Bwd Packet Length Max": max(bwd_lengths) if len(bwd_lengths) > 0 else 0,
        "Bwd Packet Length Min": min(bwd_lengths) if len(bwd_lengths) > 0 else 0,
        "Bwd Packet Length Mean": np.mean(bwd_lengths) if len(bwd_lengths) > 0 else 0,
        "Bwd Packet Length Std": np.std(bwd_lengths) if len(bwd_lengths) > 0 else 0,
        "Flow Bytes/s": sum(lengths) / flow_duration if flow_duration > 0 else 0,
        "Flow Packets/s": len(pkts) / flow_duration if flow_duration > 0 else 0,
        "Flow IAT Mean": np.mean(flow_iat),
        "Flow IAT Std": np.std(flow_iat),
        "Flow IAT Max": np.max(flow_iat),
        "Flow IAT Min": np.min(flow_iat),
        "Fwd IAT Total": np.sum(fwd_iat),
        "Fwd IAT Mean": np.mean(fwd_iat),
        "Fwd IAT Std": np.std(fwd_iat),
        "Fwd IAT Max": np.max(fwd_iat),
        "Fwd IAT Min": np.min(fwd_iat),
        "Bwd IAT Total": np.sum(bwd_iat),
        "Bwd IAT Mean": np.mean(bwd_iat),
        "Bwd IAT Std": np.std(bwd_iat),
        "Bwd IAT Max": np.max(bwd_iat),
        "Bwd IAT Min": np.min(bwd_iat),
        "Fwd PSH Flags": fwd_psh_flags,
        "Bwd PSH Flags": bwd_psh_flags,
        "Fwd URG Flags": fwd_urg_flags,
        "Bwd URG Flags": bwd_urg_flags,
        "Fwd Header Length": fwd_header_len_total,
        "Bwd Header Length": bwd_header_len_total,
        "Fwd Packets/s": len(fwd_pkts) / flow_duration if flow_duration > 0 else 0,
        "Bwd Packets/s": len(bwd_pkts) / flow_duration if flow_duration > 0 else 0,
        "Packet Length Min": min(lengths) if len(lengths) > 0 else 0,
        "Packet Length Max": max(lengths) if len(lengths) > 0 else 0,
        "Packet Length Mean": np.mean(lengths),
        "Packet Length Std": np.std(lengths),
        "Packet Length Variance": np.var(lengths),
        "FIN Flag Count": flag_counts['F'],
        "SYN Flag Count": flag_counts['S'],
        "RST Flag Count": flag_counts['R'],
        "PSH Flag Count": flag_counts['P'],
        "ACK Flag Count": flag_counts['A'],
        "URG Flag Count": flag_counts['U'],
        "CWE Flag Count": flag_counts['C'],
        "ECE Flag Count": flag_counts['E'],
        "Down/Up Ratio": down_up_ratio,
        "Avg Packet Size": np.mean(lengths),
        "Avg Fwd Segment Size": np.mean(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Avg Bwd Segment Size": np.mean(bwd_lengths) if len(bwd_lengths) > 0 else 0,
        "Fwd Avg Bytes/Bulk": np.mean(subflow_fwd_bytes_list) if subflow_fwd_bytes_list else 0,
        "Fwd Avg Packets/Bulk": np.mean(subflow_fwd_pkts_list) if subflow_fwd_pkts_list else 0,
        "Fwd Avg Bulk Rate": np.sum(subflow_fwd_bytes_list) / np.sum(fwd_iat) if np.sum(fwd_iat) > 0 else 0,
        "Bwd Avg Bytes/Bulk": np.mean(subflow_bwd_bytes_list) if subflow_bwd_bytes_list else 0,
        "Bwd Avg Packets/Bulk": np.mean(subflow_bwd_pkts_list) if subflow_bwd_pkts_list else 0,
        "Bwd Avg Bulk Rate": np.sum(subflow_bwd_bytes_list) / np.sum(bwd_iat) if np.sum(bwd_iat) > 0 else 0,
        "Subflow Fwd Packets": len(fwd_pkts),
        "Subflow Fwd Bytes": sum(fwd_lengths),
        "Subflow Bwd Packets": len(bwd_pkts),
        "Subflow Bwd Bytes": sum(bwd_lengths),
        "Init Fwd Win Bytes": init_fwd_win_bytes,
        "Init Bwd Win Bytes": init_bwd_win_bytes,
        "Fwd Act Data Packets": act_data_pkt_fwd,
        "Fwd Seg Size Min": min(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        "Active Mean": np.mean(active_periods) if len(active_periods) > 0 else 0,
        "Active Std": np.std(active_periods) if len(active_periods) > 0 else 0,
        "Active Max": np.max(active_periods) if len(active_periods) > 0 else 0,
        "Active Min": np.min(active_periods) if len(active_periods) > 0 else 0,
        "Idle Mean": np.mean(idle_periods) if len(idle_periods) > 0 else 0,
        "Idle Std": np.std(idle_periods) if len(idle_periods) > 0 else 0,
        "Idle Max": np.max(idle_periods) if len(idle_periods) > 0 else 0,
        "Idle Min": np.min(idle_periods) if len(idle_periods) > 0 else 0,
        "Label": ""  # You can fill this manually or from another source
    }
    rows.append(row)

# --- Save CSV ---
# Create DataFrame with the specific column order
df = pd.DataFrame(rows)

# Define the exact column order as requested
column_order = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total",
    "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
    "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s", "Packet Length Min",
    "Packet Length Max", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init Fwd Win Bytes",
    "Init Bwd Win Bytes", "Fwd Act Data Packets", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min", "Label"
]

# Reorder DataFrame columns
df = df[column_order]

# Save to CSV
output_filename = "data_updated.csv"
df.to_csv(output_filename, index=False)
print(f"All {len(df.columns)} flow features saved as {output_filename}")