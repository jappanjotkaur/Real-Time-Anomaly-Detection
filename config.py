# Default configuration
DEFAULT_INTERFACE = "wlp45s0"
DEFAULT_OUTPUT_DIR = "./captures"
DEFAULT_MODEL_PATH = "./model/anomaly_model.pkl"
MAX_PCAP_SIZE = 100 * 1024 * 1024  # 100MB

# Display options
TABLE_UPDATE_INTERVAL = 5          # Update the display table every 5 packets
MODEL_UPDATE_INTERVAL = 100        # Update/retrain the model every 100 packets
FLOW_ALERT_THRESHOLD = 5           # Threshold for triggering abnormal flow alerts
