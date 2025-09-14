import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import os
import sys

# The target columns based on the KDD'99 dataset
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'attack', 'difficulty'
]

# --- Mappings for Protocol and Service ---
PROTO_MAP = {1: 'icmp', 6: 'tcp', 17: 'udp'}
SERVICE_MAP = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain_u',
    67: 'dhcp', 69: 'tftp_u', 80: 'http', 110: 'pop_3', 111: 'rpc', 123: 'ntp_u',
    137: 'netbios_ns', 139: 'netbios_ssn', 143: 'imap4', 443: 'https'
}

# --- Helper Function to Determine KDD Connection Flag ---
def get_kdd_flag(pkts):
    """Approximates the KDD 'flag' feature based on TCP flags in the flow."""
    syn_count, syn_ack_count, fin_count, rst_count = 0, 0, 0, 0
    for p in pkts:
        if TCP in p:
            flags = p[TCP].flags
            if 'S' in flags and 'A' not in flags: syn_count += 1
            if 'S' in flags and 'A' in flags: syn_ack_count += 1
            if 'F' in flags: fin_count += 1
            if 'R' in flags: rst_count += 1
    
    if rst_count > 0: return 'REJ'
    if syn_count > 0 and syn_ack_count > 0 and fin_count > 0: return 'SF'
    if syn_count > 0 and syn_ack_count == 0 and rst_count == 0: return 'S0'
    if syn_count > 0 and syn_ack_count > 0 and fin_count == 0: return 'S1'
    return 'OTH'

# --- Load PCAP ---
if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} <pcap_file>")
    exit(1)
pcap_file = sys.argv[1]
if not os.path.exists(pcap_file):
    print(f"File not found: {pcap_file}")
    exit(1)
print(f"Loading packets from {pcap_file}...")
packets = rdpcap(pcap_file)

# --- Organize flows ---
# Key: (src_ip, dst_ip, src_port, dst_port, proto)
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
        
        # To keep flows bidirectional, we normalize the key
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (proto,)
        flows[key].append(pkt)

print(f"Found {len(flows)} flows. Starting feature extraction...")

# --- Stage 1: Per-flow basic feature extraction ---
flow_data = []
for key, pkts in flows.items():
    if not pkts: continue
    
    (ip1, port1), (ip2, port2), proto_num = key
    
    # Determine forward direction (first packet's source)
    first_pkt_time = min(p.time for p in pkts)
    first_pkt = [p for p in pkts if p.time == first_pkt_time][0]
    
    # -- CORRECTED CODE --
    # Safely get IP addresses and ports
    src_ip = first_pkt[IP].src
    dst_ip = first_pkt[IP].dst
    
    if TCP in first_pkt:
        src_port = first_pkt[TCP].sport
        dst_port = first_pkt[TCP].dport
    elif UDP in first_pkt:
        src_port = first_pkt[UDP].sport
        dst_port = first_pkt[UDP].dport
    else:
        # Handle packets without ports, like ICMP
        src_port = 0
        dst_port = 0
    # -- END OF CORRECTION --
    
    # Basic features
    times = sorted([float(p.time) for p in pkts])
    duration = times[-1] - times[0] if len(times) > 1 else 0.0
    
    protocol_type = PROTO_MAP.get(proto_num, 'other')
    service = SERVICE_MAP.get(dst_port, 'other')
    flag = get_kdd_flag(pkts) if protocol_type == 'tcp' else 'OTH'
    
    fwd_pkts = [p for p in pkts if p[IP].src == src_ip]
    bwd_pkts = [p for p in pkts if p[IP].src == dst_ip]
    
    src_bytes = sum(len(p.payload) for p in fwd_pkts)
    dst_bytes = sum(len(p.payload) for p in bwd_pkts)

    land = 1 if src_ip == dst_ip and src_port == dst_port else 0
    wrong_fragment = sum(1 for p in pkts if p.haslayer(IP) and p[IP].frag > 0)
    urgent = sum(1 for p in pkts if p.haslayer(TCP) and 'U' in p[TCP].flags and p[TCP].urgptr > 0)
    
    # Store intermediate data for Stage 2
    flow_data.append({
        'start_time': times[0], 'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': src_port,
        'service': service, 'flag': flag, 'duration': duration, 'protocol_type': protocol_type,
        'src_bytes': src_bytes, 'dst_bytes': dst_bytes, 'land': land, 'wrong_fragment': wrong_fragment,
        'urgent': urgent
    })

# Sort flows by start time for window-based calculations
flow_data.sort(key=lambda x: x['start_time'])

# --- Stage 2: Window-based feature extraction ---
final_rows = []
for i, current_flow in enumerate(flow_data):
    current_time = current_flow['start_time']
    
    # Time window: last 2 seconds from current flow's start
    time_window_start = current_time - 2
    time_window = [f for f in flow_data[:i+1] if f['start_time'] >= time_window_start]

    # Host window: last 100 connections to the same host
    host_connections = [f for f in flow_data[:i+1] if f['dst_ip'] == current_flow['dst_ip']]
    host_window = host_connections[-100:]
    
    # Calculate time-based features (`count`, `srv_count`, rates)
    count = len(host_connections)
    srv_count = sum(1 for f in time_window if f['service'] == current_flow['service'])
    
    serror_count = sum(1 for f in time_window if f['dst_ip'] == current_flow['dst_ip'] and f['flag'].startswith('S'))
    srv_serror_count = sum(1 for f in time_window if f['service'] == current_flow['service'] and f['flag'].startswith('S'))
    rerror_count = sum(1 for f in time_window if f['dst_ip'] == current_flow['dst_ip'] and f['flag'] == 'REJ')
    srv_rerror_count = sum(1 for f in time_window if f['service'] == current_flow['service'] and f['flag'] == 'REJ')
    
    serror_rate = serror_count / len(time_window) if time_window else 0.0
    srv_serror_rate = srv_serror_count / srv_count if srv_count > 0 else 0.0
    rerror_rate = rerror_count / len(time_window) if time_window else 0.0
    srv_rerror_rate = srv_rerror_count / srv_count if srv_count > 0 else 0.0

    same_srv_count = sum(1 for f in time_window if f['dst_ip'] == current_flow['dst_ip'] and f['service'] == current_flow['service'])
    same_srv_rate = same_srv_count / len(time_window) if time_window else 0.0
    diff_srv_rate = (len(time_window) - same_srv_count) / len(time_window) if time_window else 0.0
    
    srv_diff_host_rate = 0 # Complex to define, placeholder
    
    # Calculate host-based features (`dst_host_count`, etc.)
    dst_host_count = len(host_window)
    dst_host_srv_count = sum(1 for f in host_window if f['service'] == current_flow['service'])
    
    dst_host_same_srv_rate = dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0.0
    dst_host_diff_srv_rate = (dst_host_count - dst_host_srv_count) / dst_host_count if dst_host_count > 0 else 0.0
    dst_host_same_src_port_rate = sum(1 for f in host_window if f['src_port'] == current_flow['src_port']) / dst_host_count if dst_host_count > 0 else 0.0
    
    dst_host_srv_diff_host_rate = 0 # Complex to define, placeholder
    
    dst_host_serror_rate = sum(1 for f in host_window if f['flag'].startswith('S')) / dst_host_count if dst_host_count > 0 else 0.0
    dst_host_srv_serror_rate = sum(1 for f in host_window if f['service'] == current_flow['service'] and f['flag'].startswith('S')) / dst_host_srv_count if dst_host_srv_count > 0 else 0.0
    dst_host_rerror_rate = sum(1 for f in host_window if f['flag'] == 'REJ') / dst_host_count if dst_host_count > 0 else 0.0
    dst_host_srv_rerror_rate = sum(1 for f in host_window if f['service'] == current_flow['service'] and f['flag'] == 'REJ') / dst_host_srv_count if dst_host_srv_count > 0 else 0.0

    # Assemble the final row
    final_row = {
        'duration': current_flow['duration'], 'protocol_type': current_flow['protocol_type'], 'service': current_flow['service'],
        'flag': current_flow['flag'], 'src_bytes': current_flow['src_bytes'], 'dst_bytes': current_flow['dst_bytes'],
        'land': current_flow['land'], 'wrong_fragment': current_flow['wrong_fragment'], 'urgent': current_flow['urgent'],
        # --- Content-based features (require DPI, set to 0) ---
        'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0, 'root_shell': 0,
        'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0, 'num_access_files': 0,
        'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0,
        # --- Time-based traffic features ---
        'count': count, 'srv_count': srv_count, 'serror_rate': serror_rate, 'srv_serror_rate': srv_serror_rate,
        'rerror_rate': rerror_rate, 'srv_rerror_rate': srv_rerror_rate, 'same_srv_rate': same_srv_rate,
        'diff_srv_rate': diff_srv_rate, 'srv_diff_host_rate': srv_diff_host_rate,
        # --- Host-based traffic features ---
        'dst_host_count': dst_host_count, 'dst_host_srv_count': dst_host_srv_count, 'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate, 'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
        'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate, 'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate, 'dst_host_rerror_rate': dst_host_rerror_rate,
        'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate,
        # --- Label columns (set to default values) ---
        'attack': 'normal', 'difficulty': 0
    }
    final_rows.append(final_row)

# --- Save CSV ---
output_filename = "kdd_features.csv"
if final_rows:
    df = pd.DataFrame(final_rows, columns=COLUMNS)
    df.to_csv(output_filename, index=False)
    print(f"Success! All {len(final_rows)} flows saved to {output_filename}")
else:
    print("No valid flows found to process.")