import json
import sqlite3
import os
from datetime import datetime
from config import DB_PATH, LOG_DIR, CUSTOMERS

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create events table
    c.execute('''CREATE TABLE IF NOT EXISTS security_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  customer_id TEXT,
                  customer_name TEXT,
                  source_ip TEXT,
                  source_country TEXT,
                  source_city TEXT,
                  event_type TEXT,
                  severity INTEGER,
                  details TEXT,
                  processed INTEGER DEFAULT 0)''')
    
    # Create alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  customer_id TEXT,
                  customer_name TEXT,
                  source_ip TEXT,
                  alert_type TEXT,
                  description TEXT,
                  severity INTEGER,
                  status TEXT DEFAULT 'open')''')
    
    conn.commit()
    conn.close()

# Ingest logs from files to database
def ingest_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    for customer_id in CUSTOMERS.keys():
        log_file = os.path.join(LOG_DIR, f"{customer_id}.log")
        
        if not os.path.exists(log_file):
            continue
            
        with open(log_file, "r") as f:
            lines = f.readlines()
        
        # Process each log entry
        for line in lines:
            try:
                event = json.loads(line.strip())
                
                # Check if event already exists
                c.execute("SELECT id FROM security_events WHERE timestamp=? AND source_ip=? AND event_type=?",
                         (event["timestamp"], event["source_ip"], event["event_type"]))
                
                if c.fetchone() is None:
                    # Insert new event
                    c.execute('''INSERT INTO security_events 
                                (timestamp, customer_id, customer_name, source_ip, source_country, source_city, event_type, severity, details)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                             (event["timestamp"], event["customer_id"], event["customer_name"], 
                              event["source_ip"], event["source_country"], event["source_city"],
                              event["event_type"], event["severity"], json.dumps(event.get("details", {}))))
            
            except json.JSONDecodeError:
                print(f"Error parsing JSON in {log_file}")
        
        # Clear the log file after processing
        open(log_file, "w").close()
    
    conn.commit()
    conn.close()
    print("Log ingestion completed.")

if __name__ == "__main__":
    init_db()
    ingest_logs()