import json
import random
import time
import sqlite3
from datetime import datetime, timedelta
from config import CUSTOMERS, ATTACK_PROFILES, LOG_DIR
import os
import ipaddress

# Add fallback if LOG_INTERVAL is not in config
try:
    from config import LOG_INTERVAL
except ImportError:
    LOG_INTERVAL = 5  # Default value if not in config

# Create log directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# IP address generation with geographic diversity
def generate_ip_with_geodata():
    # Simulate IPs from different regions
    regions = [
        {"ip_range": "104.16.0.0/12", "country": "US", "city": "San Francisco"},
        {"ip_range": "31.13.64.0/18", "country": "IE", "city": "Dublin"},
        {"ip_range": "103.4.96.0/19", "country": "CN", "city": "Beijing"},
        {"ip_range": "95.85.0.0/16", "country": "NL", "city": "Amsterdam"},
        {"ip_range": "185.60.216.0/22", "country": "GB", "city": "London"},
        {"ip_range": "45.64.64.0/18", "country": "IN", "city": "Mumbai"},
        {"ip_range": "52.95.128.0/21", "country": "AU", "city": "Sydney"}
    ]
    
    region = random.choice(regions)
    network = ipaddress.ip_network(region["ip_range"])
    ip = str(network[random.randint(0, network.num_addresses - 1)])
    
    return ip, region["country"], region["city"]

# Generate simulated security events
def generate_security_event(customer_id):
    customer = CUSTOMERS[customer_id]
    attack_profile = ATTACK_PROFILES[customer_id]
    
    # Generate source IP with geographic data
    source_ip, country, city = generate_ip_with_geodata()
    
    # Determine event type based on attack profile
    event_type = random.choices(
        list(attack_profile.keys()),
        weights=list(attack_profile.values()),
        k=1
    )[0]
    
    # Common event structure
    event = {
        "timestamp": datetime.now().isoformat(),
        "customer_id": customer_id,
        "customer_name": customer["name"],
        "source_ip": source_ip,
        "source_country": country,
        "source_city": city,
        "event_type": event_type,
        "severity": random.randint(1, 10)
    }
    
    # Add event-specific details
    if event_type == "ssh_brute_force":
        event["details"] = {
            "username": random.choice(["root", "admin", "ubuntu", "ec2-user"]),
            "attempts": random.randint(5, 100),
            "protocol": "SSH"
        }
    elif event_type == "web_attacks":
        event["details"] = {
            "url": random.choice(["/wp-admin", "/api/login", "/admin"]),
            "method": random.choice(["GET", "POST"]),
            "payload": random.choice(["SQL injection", "XSS", "LFI"])
        }
    elif event_type == "data_exfiltration":
        event["details"] = {
            "data_amount": f"{random.randint(1, 1000)}MB",
            "destination": random.choice(["external-server.com", "cloud-storage.org"])
        }
    elif event_type == "credential_stuffing":
        event["details"] = {
            "target_service": random.choice(["online-banking", "email", "vpn"]),
            "credentials_tried": random.randint(10, 500)
        }
    elif event_type == "ransomware":
        event["details"] = {
            "files_encrypted": random.randint(10, 1000),
            "ransom_amount": f"${random.randint(1000, 50000)}"
        }
    
    return event

# Main log generation function
def generate_logs():
    print("Starting log generation... Press Ctrl+C to stop.")
    print(f"Log directory: {LOG_DIR}")
    print(f"Customers: {list(CUSTOMERS.keys())}")
    
    try:
        while True:
            # Generate events for each customer
            for customer_id in CUSTOMERS.keys():
                # Generate between 1-5 events per interval
                num_events = random.randint(1, 5)
                for _ in range(num_events):
                    event = generate_security_event(customer_id)
                    
                    # Write to customer-specific log file
                    log_file = os.path.join(LOG_DIR, f"{customer_id}.log")
                    with open(log_file, "a") as f:
                        f.write(json.dumps(event) + "\n")
                    
                    print(f"Generated {event['event_type']} event for {customer_id} from IP {event['source_ip']}")
            
            print(f"Waiting {LOG_INTERVAL} seconds before next batch...")
            time.sleep(LOG_INTERVAL)
    except KeyboardInterrupt:
        print("Log generation stopped.")
    except Exception as e:
        print(f"Error in log generation: {e}")

if __name__ == "__main__":
    generate_logs()