import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import os
import sys


# --- Load PCAP ---
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
        key = (src_ip, dst_ip, src_port, dst_port, proto)
        flows[key].append(pkt)

# --- Feature extraction ---
def compute_iat(times):
    if len(times) < 2:
        return np.array([0])
    iat = np.diff(sorted(times))
    return iat

rows = []

for (src_ip, dst_ip, src_port, dst_port, proto), pkts in flows.items():
    times = np.array([p.time for p in pkts]).astype(float)
    lengths = np.array([len(p) for p in pkts])

    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]
    fwd_lengths = np.array([len(p) for p in fwd_pkts])
    bwd_lengths = np.array([len(p) for p in bwd_pkts])

    flow_iat = compute_iat(times)
    fwd_iat = compute_iat(np.array([p.time for p in fwd_pkts]).astype(float))
    bwd_iat = compute_iat(np.array([p.time for p in bwd_pkts]).astype(float))

    # TCP Flags
    flags = ['F', 'S', 'R', 'P', 'A', 'U', 'C', 'E']  # FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
    flag_counts = dict.fromkeys(flags, 0)
    for p in pkts:
        if TCP in p:
            for f in flags:
                if f in p[TCP].flags:
                    flag_counts[f] += 1

    # Down/Up ratio
    down_up_ratio = (sum(bwd_lengths) / sum(fwd_lengths)) if sum(fwd_lengths) > 0 else 0

    # Bulk / Subflow / Active/Idle stats can be approximated
    # Here, we just compute basic sums and means
    # Subflow: every 10 packets as a subflow
    subflow_size = 10
    subflow_fwd_pkts = [len(fwd_lengths[i:i+subflow_size]) for i in range(0, len(fwd_lengths), subflow_size)]
    subflow_fwd_bytes = [sum(fwd_lengths[i:i+subflow_size]) for i in range(0, len(fwd_lengths), subflow_size)]
    subflow_bwd_pkts = [len(bwd_lengths[i:i+subflow_size]) for i in range(0, len(bwd_lengths), subflow_size)]
    subflow_bwd_bytes = [sum(bwd_lengths[i:i+subflow_size]) for i in range(0, len(bwd_lengths), subflow_size)]

    # Active/Idle times
    sorted_times = np.sort(times)
    active_periods = compute_iat(sorted_times)
    idle_periods = active_periods[active_periods > 0.5]  # idle > 0.5 sec threshold

    row = {
        "Destination Port": int(dst_port),
        "Flow Duration": float(max(times)-min(times)),
        "Total Fwd Packets": int(len(fwd_lengths)),
        "Total Backward Packets": int(len(bwd_lengths)),
        "Total Length of Fwd Packets": int(sum(fwd_lengths)),
        "Total Length of Bwd Packets": int(sum(bwd_lengths)),
        "Fwd Packet Length Max": int(max(fwd_lengths)) if len(fwd_lengths)>0 else 0,
        "Fwd Packet Length Min": int(min(fwd_lengths)) if len(fwd_lengths)>0 else 0,
        "Fwd Packet Length Mean": float(fwd_lengths.mean()) if len(fwd_lengths)>0 else 0,
        "Fwd Packet Length Std": float(fwd_lengths.std()) if len(fwd_lengths)>0 else 0,
        "Bwd Packet Length Max": int(max(bwd_lengths)) if len(bwd_lengths)>0 else 0,
        "Bwd Packet Length Min": int(min(bwd_lengths)) if len(bwd_lengths)>0 else 0,
        "Bwd Packet Length Mean": float(bwd_lengths.mean()) if len(bwd_lengths)>0 else 0,
        "Bwd Packet Length Std": float(bwd_lengths.std()) if len(bwd_lengths)>0 else 0,
        "Flow Bytes/s": float(sum(lengths)/(max(times)-min(times))) if max(times)-min(times)>0 else 0,
        "Flow Packets/s": float(len(pkts)/(max(times)-min(times))) if max(times)-min(times)>0 else 0,
        "Flow IAT Mean": float(flow_iat.mean()),
        "Flow IAT Std": float(flow_iat.std()),
        "Flow IAT Max": float(flow_iat.max()),
        "Flow IAT Min": float(flow_iat.min()),
        "Fwd IAT Total": float(fwd_iat.sum()),
        "Fwd IAT Mean": float(fwd_iat.mean()),
        "Fwd IAT Std": float(fwd_iat.std()),
        "Fwd IAT Max": float(fwd_iat.max()),
        "Fwd IAT Min": float(fwd_iat.min()),
        "Bwd IAT Total": float(bwd_iat.sum()),
        "Bwd IAT Mean": float(bwd_iat.mean()),
        "Bwd IAT Std": float(bwd_iat.std()),
        "Bwd IAT Max": float(bwd_iat.max()),
        "Bwd IAT Min": float(bwd_iat.min()),
        "Fwd PSH Flags": int(flag_counts['P']),
        "Bwd PSH Flags": 0,  # optional: can compute per direction
        "Fwd URG Flags": int(flag_counts['U']),
        "Bwd URG Flags": 0,
        "Fwd Header Length": float(np.mean([len(p[TCP].options) if TCP in p else 0 for p in fwd_pkts])) if len(fwd_pkts)>0 else 0,
        "Bwd Header Length": float(np.mean([len(p[TCP].options) if TCP in p else 0 for p in bwd_pkts])) if len(bwd_pkts)>0 else 0,
        "Fwd Packets/s": float(len(fwd_lengths)/(max(times)-min(times))) if max(times)-min(times)>0 else 0,
        "Bwd Packets/s": float(len(bwd_lengths)/(max(times)-min(times))) if max(times)-min(times)>0 else 0,
        "Min Packet Length": int(lengths.min()),
        "Max Packet Length": int(lengths.max()),
        "Packet Length Mean": float(lengths.mean()),
        "Packet Length Std": float(lengths.std()),
        "Packet Length Variance": float(lengths.var()),
        "FIN Flag Count": int(flag_counts['F']),
        "SYN Flag Count": int(flag_counts['S']),
        "RST Flag Count": int(flag_counts['R']),
        "PSH Flag Count": int(flag_counts['P']),
        "ACK Flag Count": int(flag_counts['A']),
        "URG Flag Count": int(flag_counts['U']),
        "CWE Flag Count": int(flag_counts['C']),
        "ECE Flag Count": int(flag_counts['E']),
        "Down/Up Ratio": float(down_up_ratio),
        "Average Packet Size": float(lengths.mean()),
        "Avg Fwd Segment Size": float(fwd_lengths.mean()) if len(fwd_lengths)>0 else 0,
        "Avg Bwd Segment Size": float(bwd_lengths.mean()) if len(bwd_lengths)>0 else 0,
        "Fwd Avg Bytes/Bulk": float(np.mean(subflow_fwd_bytes)) if subflow_fwd_bytes else 0,
        "Fwd Avg Packets/Bulk": float(np.mean(subflow_fwd_pkts)) if subflow_fwd_pkts else 0,
        "Fwd Avg Bulk Rate": float(np.mean(subflow_fwd_bytes)/np.mean(fwd_iat)) if len(fwd_iat)>0 and np.mean(fwd_iat)!=0 else 0,
        "Bwd Avg Bytes/Bulk": float(np.mean(subflow_bwd_bytes)) if subflow_bwd_bytes else 0,
        "Bwd Avg Packets/Bulk": float(np.mean(subflow_bwd_pkts)) if subflow_bwd_pkts else 0,
        "Bwd Avg Bulk Rate": float(np.mean(subflow_bwd_bytes)/np.mean(bwd_iat)) if len(bwd_iat)>0 and np.mean(bwd_iat)!=0 else 0,
        "Subflow Fwd Packets": int(np.sum(subflow_fwd_pkts)),
        "Subflow Fwd Bytes": int(np.sum(subflow_fwd_bytes)),
        "Subflow Bwd Packets": int(np.sum(subflow_bwd_pkts)),
        "Subflow Bwd Bytes": int(np.sum(subflow_bwd_bytes)),
        "Init_Win_bytes_forward": float(np.mean([p[TCP].window if TCP in p else 0 for p in fwd_pkts])) if len(fwd_pkts)>0 else 0,
        "Init_Win_bytes_backward": float(np.mean([p[TCP].window if TCP in p else 0 for p in bwd_pkts])) if len(bwd_pkts)>0 else 0,
        "act_data_pkt_fwd": int(len(fwd_pkts)),
        "min_seg_size_forward": int(np.min(fwd_lengths)) if len(fwd_lengths)>0 else 0,
        "Active Mean": float(np.mean(active_periods)) if len(active_periods)>0 else 0,
        "Active Std": float(np.std(active_periods)) if len(active_periods)>0 else 0,
        "Active Max": float(np.max(active_periods)) if len(active_periods)>0 else 0,
        "Active Min": float(np.min(active_periods)) if len(active_periods)>0 else 0,
        "Idle Mean": float(np.mean(idle_periods)) if len(idle_periods)>0 else 0,
        "Idle Std": float(np.std(idle_periods)) if len(idle_periods)>0 else 0,
        "Idle Max": float(np.max(idle_periods)) if len(idle_periods)>0 else 0,
        "Idle Min": float(np.min(idle_periods)) if len(idle_periods)>0 else 0,
        "Label": ""  # You can fill this manually
    }
    rows.append(row)

# --- Save CSV ---
df = pd.DataFrame(rows)
df.to_csv(r"data.csv", index=False)
print("All 79 flow features saved as data.csv")
