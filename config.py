# Configuration for Shai DevSecOps AI Assistant

# Demo customer information
CUSTOMERS = {
    "acme_corp": {
        "name": "Acme Corp",
        "industry": "Technology",
        "hq_coords": (37.7749, -122.4194),  # San Francisco
        "ip_range": "192.168.10.0/24",
        "assets": ["web-server-1", "db-server-1", "app-server-1"]
    },
    "beta_bank": {
        "name": "Beta Bank",
        "industry": "Finance",
        "hq_coords": (40.7128, -74.0060),  # New York
        "ip_range": "192.168.20.0/24",
        "assets": ["core-banking-1", "atm-network-1", "customer-db-1"]
    },
    "gamma_health": {
        "name": "Gamma Healthcare",
        "industry": "Healthcare",
        "hq_coords": (42.3601, -71.0589),  # Boston
        "ip_range": "192.168.30.0/24",
        "assets": ["ehr-server-1", "lab-system-1", "patient-portal-1"]
    }
}

# File paths
LOG_DIR = "logs"
DB_PATH = "shai_security.db"
BLOCKED_IPS_FILE = "blocked_ips.json"
CONTAINED_ASSETS_FILE = "contained_assets.json"

# Simulation parameters
LOG_INTERVAL = 5  # seconds between log generation
ATTACK_PROFILES = {
    "acme_corp": {"ssh_brute_force": 0.6, "web_attacks": 0.3, "data_exfiltration": 0.1},
    "beta_bank": {"credential_stuffing": 0.5, "api_abuse": 0.3, "financial_fraud": 0.2},
    "gamma_health": {"ransomware": 0.4, "data_theft": 0.4, "service_disruption": 0.2}
}

# AI Model parameters
ANOMALY_THRESHOLD = 0.7  # Threshold for flagging anomalies