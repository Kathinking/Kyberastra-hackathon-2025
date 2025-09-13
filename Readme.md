# Network Flow Feature Extraction & Live Capture

This project provides Python scripts to **capture network traffic**, **extract flow-based features from PCAP files**, and save the results into a CSV file. It is useful for network analysis, anomaly detection, and machine learning tasks involving traffic classification.

---

## 📂 Files

1. **`new_fixed.py`**  
   - Takes a `.pcap` file as input.  
   - Extracts **79 flow-based features** per network flow (e.g., packet lengths, inter-arrival times, TCP flags, idle times, etc.).  
   - Outputs the extracted features into `data.csv`.

2. **`capture_and_analyze.py`**  
   - Automates live network capture using **Tshark**.  
   - Captures traffic for a fixed duration (default: 5 seconds).  
   - Saves the capture into `data.pcap`.  
   - Runs `new_fixed.py` on the captured file to extract features into `data.csv`.  
   - Repeats this process in a loop until stopped.

---

## ⚙️ Requirements

- **Python 3.7+**
- Python libraries:
  ```bash
  pip install scapy pandas numpy
  ```
- **Wireshark/Tshark** installed:
  - [Download Wireshark](https://www.wireshark.org/download.html)
  - Ensure `tshark` is in your system PATH or update `TSHARK_PATH` in `capture_and_analyze.py`.

---

## 🚀 Usage

### 1. Run feature extraction on an existing PCAP
```bash
python new_fixed.py <path_to_pcap>
```

Example:
```bash
python new_fixed.py data.pcap
```
This will create `data.csv` with 79 extracted features per flow.

---

### 2. Run live capture & analysis loop
Edit **`capture_and_analyze.py`** to configure:
- `TSHARK_PATH` → Path to `tshark.exe` or `tshark` binary.
- `INTERFACE_NAME` → Name of your network interface (run `tshark -D` to list).
- `ANALYSIS_SCRIPT_PATH` → Path to `new_fixed.py`.

Then run:
```bash
python capture_and_analyze.py
```
This will:
1. Capture 5 seconds of traffic.
2. Save it to `data.pcap`.
3. Extract features into `data.csv`.
4. Repeat until you press **Ctrl+C** to stop.

---

## 📝 Notes

- The extracted CSV includes an empty **`Label`** column for manual annotation (e.g., Normal/Abnormal traffic).
- You may extend the analysis script to integrate anomaly detection or ML classification.
- Run the capture script with administrator/root privileges if required by Tshark.

---

## 📊 Example Output
After running, you will get a `data.csv` file with columns such as:

- `Flow Duration`
- `Total Fwd Packets`
- `Total Backward Packets`
- `Flow IAT Mean`
- `Packet Length Mean`
- `SYN Flag Count`
- `ACK Flag Count`
- `Active Mean`
- `Idle Mean`
- `Label`

---

## 🛑 Troubleshooting

- **`File not found: <pcap>`** → Ensure the PCAP file exists.
- **`Tshark not found`** → Update `TSHARK_PATH` in `capture_and_analyze.py`.
- **`Permission denied`** → Run as Administrator (Windows) or `sudo` (Linux/macOS).
- **`Interface not found`** → Run `tshark -D` to list available interfaces and update `INTERFACE_NAME`.

---

## 📌 License
MIT License – Free to use and modify.

---

## ✨ Author
Developed for **network traffic analysis and anomaly detection research**.

