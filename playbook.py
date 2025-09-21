import json
import os
from datetime import datetime
from config import BLOCKED_IPS_FILE, CONTAINED_ASSETS_FILE

# Initialize response files
def init_response_files():
    # Initialize blocked IPs file
    if not os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump({"blocked_ips": []}, f)
    
    # Initialize contained assets file
    if not os.path.exists(CONTAINED_ASSETS_FILE):
        with open(CONTAINED_ASSETS_FILE, "w") as f:
            json.dump({"contained_assets": []}, f)

# Block an IP address across all systems
def block_ip(ip_address, reason=""):
    init_response_files()  # Ensure files exist
    
    # Load currently blocked IPs
    with open(BLOCKED_IPS_FILE, "r") as f:
        data = json.load(f)
    
    # Add new IP if not already blocked
    if ip_address not in [ip["ip"] for ip in data["blocked_ips"]]:
        data["blocked_ips"].append({
            "ip": ip_address,
            "timestamp": datetime.now().isoformat(),
            "reason": reason
        })
        
        # Save updated list
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(data, f, indent=2)
        
        return f"IP {ip_address} blocked successfully."
    else:
        return f"IP {ip_address} is already blocked."

# Contain a compromised asset
def contain_asset(asset_name, reason=""):
    init_response_files()  # Ensure files exist
    
    # Load currently contained assets
    with open(CONTAINED_ASSETS_FILE, "r") as f:
        data = json.load(f)
    
    # Add new asset if not already contained
    if asset_name not in [a["name"] for a in data["contained_assets"]]:
        data["contained_assets"].append({
            "name": asset_name,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "status": "contained"
        })
        
        # Save updated list
        with open(CONTAINED_ASSETS_FILE, "w") as f:
            json.dump(data, f, indent=2)
        
        return f"Asset {asset_name} contained successfully."
    else:
        return f"Asset {asset_name} is already contained."

# Get list of blocked IPs
def get_blocked_ips():
    init_response_files()  # Ensure files exist
    with open(BLOCKED_IPS_FILE, "r") as f:
        data = json.load(f)
    return data["blocked_ips"]

# Get list of contained assets
def get_contained_assets():
    init_response_files()  # Ensure files exist
    with open(CONTAINED_ASSETS_FILE, "r") as f:
        data = json.load(f)
    return data["contained_assets"]

# Check if an IP is blocked
def is_ip_blocked(ip_address):
    blocked_ips = get_blocked_ips()
    return any(ip["ip"] == ip_address for ip in blocked_ips)

# Check if an asset is contained
def is_asset_contained(asset_name):
    contained_assets = get_contained_assets()
    return any(asset["name"] == asset_name for asset in contained_assets)

if __name__ == "__main__":
    init_response_files()