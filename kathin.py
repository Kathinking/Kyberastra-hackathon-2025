import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import os
import sys

# The new target columns for feature extraction
COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
]

# Helper function for statistical calculations to avoid repetition
def calculate_stats(data_list):
    """Calculates max, min, mean, and standard deviation for a list of numbers."""
    if not data_list:
        return 0, 0, 0, 0
    data_array = np.array(data_list)
    return np.max(data_array), np.min(data_array), np.mean(data_array), np.std(data_array)

# --- Script Start ---
if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <pcap_file>")
    sys.exit(1)
pcap_file = sys.argv[1]
if not os.path.exists(pcap_file):
    print(f"File not found: {pcap_file}")
    sys.exit(1)
print(f"Loading packets from {pcap_file}...")
packets = rdpcap(pcap_file)

# --- Organize packets into flows ---
# Flow key is a tuple of sorted IPs/ports and protocol to handle bidirectional traffic
flows = defaultdict(list)
for pkt in packets:
    if IP in pkt:
        proto = pkt[IP].proto
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        src_port, dst_port = (0, 0)
        if TCP in pkt:
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport

        # Normalize the key to group packets from the same flow together
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        flows[key].append(pkt)

print(f"Found {len(flows)} flows. Starting feature extraction...")

# --- Feature Extraction Loop ---
flow_features_list = []
for key, pkts in flows.items():
    if not pkts:
        continue
    
    # Sort packets by their timestamp to ensure correct order
    pkts.sort(key=lambda p: p.time)
    
    # --- Flow Identification and Timestamps ---
    first_pkt = pkts[0]
    src_ip = first_pkt[IP].src
    dst_ip = first_pkt[IP].dst
    
    if TCP in first_pkt:
        src_port = first_pkt[TCP].sport
        dst_port = first_pkt[TCP].dport
    elif UDP in first_pkt:
        src_port = first_pkt[UDP].sport
        dst_port = first_pkt[UDP].dport
    else: # For protocols like ICMP that don't have ports
        src_port, dst_port = 0, 0

    times = [float(p.time) for p in pkts]
    # Flow duration in microseconds
    flow_duration = (times[-1] - times[0]) * 1e6 if len(times) > 1 else 0
    
    # --- Packet Separation (Forward/Backward) ---
    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]
    
    # --- Packet Length Statistics ---
    fwd_pkt_lengths = [len(p) for p in fwd_pkts]
    bwd_pkt_lengths = [len(p) for p in bwd_pkts]
    all_pkt_lengths = fwd_pkt_lengths + bwd_pkt_lengths

    fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std = calculate_stats(fwd_pkt_lengths)
    bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std = calculate_stats(bwd_pkt_lengths)
    pkt_len_max, pkt_len_min, pkt_len_mean, pkt_len_std = calculate_stats(all_pkt_lengths)
    pkt_len_var = np.var(np.array(all_pkt_lengths)) if all_pkt_lengths else 0
    
    # --- Rate Calculations ---
    duration_sec = flow_duration / 1e6
    flow_bytes_s = sum(all_pkt_lengths) / duration_sec if duration_sec > 0 else 0
    flow_packets_s = len(pkts) / duration_sec if duration_sec > 0 else 0
    fwd_packets_s = len(fwd_pkts) / duration_sec if duration_sec > 0 else 0
    bwd_packets_s = len(bwd_pkts) / duration_sec if duration_sec > 0 else 0

    # --- Inter-Arrival Time (IAT) Statistics (in microseconds) ---
    flow_iat = np.diff(times) * 1e6 if len(times) > 1 else []
    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = (np.mean(flow_iat), np.std(flow_iat), np.max(flow_iat), np.min(flow_iat)) if len(flow_iat) > 0 else (0,0,0,0)

    fwd_times = sorted([float(p.time) for p in fwd_pkts])
    fwd_iat = np.diff(fwd_times) * 1e6 if len(fwd_times) > 1 else []
    fwd_iat_total = (fwd_times[-1] - fwd_times[0]) * 1e6 if len(fwd_times) > 1 else 0
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = (np.mean(fwd_iat), np.std(fwd_iat), np.max(fwd_iat), np.min(fwd_iat)) if len(fwd_iat) > 0 else (0,0,0,0)

    bwd_times = sorted([float(p.time) for p in bwd_pkts])
    bwd_iat = np.diff(bwd_times) * 1e6 if len(bwd_times) > 1 else []
    bwd_iat_total = (bwd_times[-1] - bwd_times[0]) * 1e6 if len(bwd_times) > 1 else 0
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = (np.mean(bwd_iat), np.std(bwd_iat), np.max(bwd_iat), np.min(bwd_iat)) if len(bwd_iat) > 0 else (0,0,0,0)

    # --- Flag Counts ---
    fwd_psh_flags, bwd_psh_flags, fwd_urg_flags, bwd_urg_flags = 0, 0, 0, 0
    fin_count, syn_count, rst_count, psh_count, ack_count, urg_count, cwe_count, ece_count = 0, 0, 0, 0, 0, 0, 0, 0

    for p in pkts:
        if TCP in p:
            flags = p[TCP].flags
            is_fwd = p[IP].src == src_ip
            if 'F' in flags: fin_count += 1
            if 'S' in flags: syn_count += 1
            if 'R' in flags: rst_count += 1
            if 'P' in flags:
                psh_count += 1
                if is_fwd: fwd_psh_flags += 1
                else: bwd_psh_flags += 1
            if 'A' in flags: ack_count += 1
            if 'U' in flags:
                urg_count += 1
                if is_fwd: fwd_urg_flags += 1
                else: bwd_urg_flags += 1
            if 'E' in flags: ece_count += 1
            if 'C' in flags: cwe_count += 1
    
    # --- Header Lengths (in bytes) ---
    fwd_header_len = sum(p[IP].ihl * 4 for p in fwd_pkts if IP in p)
    bwd_header_len = sum(p[IP].ihl * 4 for p in bwd_pkts if IP in p)
    
    # --- Other Features ---
    down_up_ratio = len(bwd_pkts) / len(fwd_pkts) if len(fwd_pkts) > 0 else 0
    
    # --- Subflow and Window Features ---
    init_win_fwd = fwd_pkts[0][TCP].window if fwd_pkts and TCP in fwd_pkts[0] else 0
    init_win_bwd = bwd_pkts[0][TCP].window if bwd_pkts and TCP in bwd_pkts[0] else 0
    act_data_pkt_fwd = sum(1 for p in fwd_pkts if TCP in p and hasattr(p[TCP], 'payload') and len(p[TCP].payload) > 0)
    min_seg_size_fwd = fwd_pkts[0][IP].ihl * 4 + fwd_pkts[0][TCP].dataofs * 4 if fwd_pkts and TCP in fwd_pkts[0] else 0
    
    # --- Active/Idle Time Calculation (in microseconds) ---
    idle_times, active_times = [], []
    if len(flow_iat) > 0:
        idle_threshold = 1_000_000  # 1 second
        current_active_start = times[0]
        for i, iat in enumerate(flow_iat):
            if iat > idle_threshold:
                active_duration = (times[i] - current_active_start) * 1e6
                if active_duration > 0: active_times.append(active_duration)
                idle_times.append(iat)
                current_active_start = times[i+1]
        final_active_duration = (times[-1] - current_active_start) * 1e6
        if final_active_duration > 0: active_times.append(final_active_duration)

    active_mean, active_std, active_max, active_min = (np.mean(active_times), np.std(active_times), np.max(active_times), np.min(active_times)) if active_times else (0,0,0,0)
    idle_mean, idle_std, idle_max, idle_min = (np.mean(idle_times), np.std(idle_times), np.max(idle_times), np.min(idle_times)) if idle_times else (0,0,0,0)

    # --- Assemble final feature dictionary ---
    features = {
        'Destination Port': dst_port, 'Flow Duration': flow_duration, 'Total Fwd Packets': len(fwd_pkts),
        'Total Backward Packets': len(bwd_pkts), 'Total Length of Fwd Packets': sum(fwd_pkt_lengths),
        'Total Length of Bwd Packets': sum(bwd_pkt_lengths), 'Fwd Packet Length Max': fwd_len_max,
        'Fwd Packet Length Min': fwd_len_min, 'Fwd Packet Length Mean': fwd_len_mean, 'Fwd Packet Length Std': fwd_len_std,
        'Bwd Packet Length Max': bwd_len_max, 'Bwd Packet Length Min': bwd_len_min, 'Bwd Packet Length Mean': bwd_len_mean,
        'Bwd Packet Length Std': bwd_len_std, 'Flow Bytes/s': flow_bytes_s, 'Flow Packets/s': flow_packets_s,
        'Flow IAT Mean': flow_iat_mean, 'Flow IAT Std': flow_iat_std, 'Flow IAT Max': flow_iat_max, 'Flow IAT Min': flow_iat_min,
        'Fwd IAT Total': fwd_iat_total, 'Fwd IAT Mean': fwd_iat_mean, 'Fwd IAT Std': fwd_iat_std, 'Fwd IAT Max': fwd_iat_max,
        'Fwd IAT Min': fwd_iat_min, 'Bwd IAT Total': bwd_iat_total, 'Bwd IAT Mean': bwd_iat_mean, 'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max, 'Bwd IAT Min': bwd_iat_min, 'Fwd PSH Flags': fwd_psh_flags, 'Bwd PSH Flags': bwd_psh_flags,
        'Fwd URG Flags': fwd_urg_flags, 'Bwd URG Flags': bwd_urg_flags, 'Fwd Header Length': fwd_header_len,
        'Bwd Header Length': bwd_header_len, 'Fwd Packets/s': fwd_packets_s, 'Bwd Packets/s': bwd_packets_s,
        'Min Packet Length': pkt_len_min, 'Max Packet Length': pkt_len_max, 'Packet Length Mean': pkt_len_mean,
        'Packet Length Std': pkt_len_std, 'Packet Length Variance': pkt_len_var, 'FIN Flag Count': fin_count,
        'SYN Flag Count': syn_count, 'RST Flag Count': rst_count, 'PSH Flag Count': psh_count, 'ACK Flag Count': ack_count,
        'URG Flag Count': urg_count, 'CWE Flag Count': cwe_count, 'ECE Flag Count': ece_count, 'Down/Up Ratio': down_up_ratio,
        'Average Packet Size': pkt_len_mean, 'Avg Fwd Segment Size': fwd_len_mean, 'Avg Bwd Segment Size': bwd_len_mean,
        'Fwd Header Length.1': fwd_header_len, 'Fwd Avg Bytes/Bulk': 0, 'Fwd Avg Packets/Bulk': 0, 'Fwd Avg Bulk Rate': 0,
        'Bwd Avg Bytes/Bulk': 0, 'Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': len(fwd_pkts),
        'Subflow Fwd Bytes': sum(fwd_pkt_lengths), 'Subflow Bwd Packets': len(bwd_pkts), 'Subflow Bwd Bytes': sum(bwd_pkt_lengths),
        'Init_Win_bytes_forward': init_win_fwd, 'Init_Win_bytes_backward': init_win_bwd, 'act_data_pkt_fwd': act_data_pkt_fwd,
        'min_seg_size_forward': min_seg_size_fwd, 'Active Mean': active_mean, 'Active Std': active_std, 'Active Max': active_max,
        'Active Min': active_min, 'Idle Mean': idle_mean, 'Idle Std': idle_std, 'Idle Max': idle_max, 'Idle Min': idle_min,
        'Label': 'BENIGN' # Default label
    }
    flow_features_list.append(features)

# --- Save to CSV ---
output_filename = "extracted_features.csv"
if flow_features_list:
    df = pd.DataFrame(flow_features_list, columns=COLUMNS)
    # Fill any potential NaN values with 0
    df.fillna(0, inplace=True)
    df.to_csv(output_filename, index=False)
    print(f"Success! All {len(flow_features_list)} flows saved to {output_filename}")
else:
    print("No valid flows found to process.")