import subprocess
import time
import sys

# --- CONFIGURATION ---
# TODO: Set the correct path to your tshark.exe
# Common paths:
# Windows: "C:\\Program Files\\Wireshark\\tshark.exe"
# Linux/macOS: "tshark" (if it's in your system's PATH)
TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"

# TODO: Set the network interface you want to capture.
# Run 'tshark -D' in your terminal to see a list of available interfaces.
# Example: "Wi-Fi", "Ethernet", "en0"
INTERFACE_NAME = "Wi-Fi"

# Hardcoded path to your analysis script
ANALYSIS_SCRIPT_PATH = "new_fixed.py"

# File settings
CAPTURE_DURATION = 5
OUTPUT_FILENAME = "data.pcap"


def run_capture_cycle():
    """
    Runs one cycle of capturing traffic and then analyzing it.
    """
    print(f"--- Starting {CAPTURE_DURATION} second network capture on '{INTERFACE_NAME}' ---")

    # 1. Construct and run the Tshark command to capture packets
    tshark_command = [
        TSHARK_PATH,
        '-i', INTERFACE_NAME,
        '-a', f'duration:{CAPTURE_DURATION}',
        '-w', OUTPUT_FILENAME
    ]

    try:
        # This command will run for 5 seconds and then automatically stop
        capture_process = subprocess.run(
            tshark_command,
            capture_output=True, text=True, check=True
        )
        print(f"Capture successful. Data saved to '{OUTPUT_FILENAME}'.")

    except FileNotFoundError:
        print(f"ERROR: Tshark not found at '{TSHARK_PATH}'.")
        print("Please check your Wireshark installation and the TSHARK_PATH variable.")
        sys.exit(1) # Exit the script if tshark isn't found
    except subprocess.CalledProcessError as e:
        print(f"ERROR during capture on interface '{INTERFACE_NAME}':")
        print(e.stderr) # Tshark often prints errors to stderr
        print("Please ensure the interface name is correct and you have permissions to capture.")
        return # Skip analysis and try again

    print(f"\n--- Running analysis script on '{OUTPUT_FILENAME}' ---")

    # 2. Construct and run the analysis script command
    analysis_command = ["python", ANALYSIS_SCRIPT_PATH, OUTPUT_FILENAME]

    try:
        analysis_process = subprocess.run(
            analysis_command,
            capture_output=True, text=True, check=True
        )
        # Print the output from the analysis script
        print(analysis_process.stdout)
    except FileNotFoundError:
        print(f"ERROR: Analysis script not found at '{ANALYSIS_SCRIPT_PATH}'.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("ERROR during analysis script execution:")
        print(e.stderr)

if __name__ == "__main__":
    try:
        while True:
            run_capture_cycle()
            print("\nNext cycle will start in a moment...")
            print("-" * 50)
            # The capture itself takes 5 seconds, so the loop effectively runs "every 5 seconds".
            # You can add a time.sleep(SECONDS) here if you want an extra delay.
    except KeyboardInterrupt:
        print("\nLoop stopped by user. Exiting.")