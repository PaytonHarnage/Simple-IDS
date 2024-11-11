import logging
import scapy.all as scapy
import re

# Set up logging to track detected intrusions
logging.basicConfig(filename="ids.log", level=logging.INFO)

# Define suspicious patterns for attack detection
suspicious_patterns = {
    "brute_force": re.compile(r"failed login|incorrect password", re.IGNORECASE),
    "port_scanning": re.compile(r"nmap|masscan", re.IGNORECASE),
}

# Function to log potential intrusions
def log_intrusion(message, packet):
    """Log intrusion message and packet details."""
    logging.warning(f"Suspicious activity detected: {message}")
    logging.info(f"Packet details: {packet.summary()}")

# Function to detect brute-force attempts
def detect_brute_force(packet):
    """Check for patterns in packets that suggest brute-force attempts."""
    if packet.haslayer(scapy.IP):
        payload = str(packet.payload)
        if suspicious_patterns["brute_force"].search(payload):
            log_intrusion("Potential brute-force attack detected.", packet)

# Function to detect port scanning
def detect_port_scanning(packet):
    """Detect possible port scanning based on traffic patterns."""
    if packet.haslayer(scapy.IP):
        payload = str(packet.payload)
        if suspicious_patterns["port_scanning"].search(payload):
            log_intrusion("Port scanning detected.", packet)

# Function to process and analyze captured packets
def process_packet(packet):
    """Process captured network packet and check for suspicious activity."""
    detect_brute_force(packet)
    detect_port_scanning(packet)

# Main function to capture network traffic
def start_ids():
    """Start the IDS to monitor network traffic."""
    print("Starting Intrusion Detection System...\n")
    scapy.sniff(prn=process_packet, store=0)

# Run the IDS
if __name__ == "__main__":
    start_ids()
