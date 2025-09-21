import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
from config import DB_PATH, ANOMALY_THRESHOLD

# Feature engineering for anomaly detection
def extract_features(events_df):
    features = []
    
    for _, event in events_df.iterrows():
        # Convert event to feature vector
        feature_vec = [
            event['severity'],
            len(event['source_ip'].split('.')),
            1 if event['source_country'] != 'US' else 0,  # Foreign origin flag
        ]
        
        # Add event type indicators
        event_types = ['ssh_brute_force', 'web_attacks', 'data_exfiltration', 
                      'credential_stuffing', 'ransomware', 'api_abuse']
        for et in event_types:
            feature_vec.append(1 if event['event_type'] == et else 0)
            
        features.append(feature_vec)
    
    return np.array(features)

# Detect anomalies using Isolation Forest
def detect_anomalies():
    conn = sqlite3.connect(DB_PATH)
    
    # Get events from the last hour that haven't been processed
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    events_df = pd.read_sql_query(
        "SELECT * FROM security_events WHERE timestamp > ? AND processed = 0",
        conn, params=(one_hour_ago,)
    )
    
    if len(events_df) == 0:
        return []
    
    # Extract features
    X = extract_features(events_df)
    
    # Train Isolation Forest model
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)
    
    # Predict anomalies
    predictions = clf.decision_function(X)
    events_df['anomaly_score'] = predictions
    
    # Identify anomalies
    anomalies = events_df[events_df['anomaly_score'] < ANOMALY_THRESHOLD]
    
    # Generate alerts for anomalies
    alerts = []
    for _, anomaly in anomalies.iterrows():
        alert = {
            'timestamp': datetime.now().isoformat(),
            'customer_id': anomaly['customer_id'],
            'customer_name': anomaly['customer_name'],
            'source_ip': anomaly['source_ip'],
            'alert_type': 'anomaly_detected',
            'description': f"Anomalous {anomaly['event_type']} activity detected from {anomaly['source_ip']}",
            'severity': min(10, anomaly['severity'] + 2)  # Increase severity for anomalies
        }
        alerts.append(alert)
    
    # Mark events as processed
    event_ids = events_df['id'].tolist()
    if event_ids:
        placeholders = ','.join(['?'] * len(event_ids))
        conn.execute(f"UPDATE security_events SET processed = 1 WHERE id IN ({placeholders})", event_ids)
    
    # Save alerts to database
    if alerts:
        for alert in alerts:
            conn.execute('''INSERT INTO alerts 
                         (timestamp, customer_id, customer_name, source_ip, alert_type, description, severity)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (alert['timestamp'], alert['customer_id'], alert['customer_name'],
                      alert['source_ip'], alert['alert_type'], alert['description'], alert['severity']))
    
    conn.commit()
    conn.close()
    
    return alerts

# Collective intelligence - detect attacks across multiple customers
def detect_cross_customer_attacks():
    conn = sqlite3.connect(DB_PATH)
    
    # Get recent events from all customers
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    events_df = pd.read_sql_query(
        "SELECT * FROM security_events WHERE timestamp > ?",
        conn, params=(one_hour_ago,)
    )
    
    # Group by source IP to find attackers targeting multiple customers
    ip_activity = events_df.groupby('source_ip').agg({
        'customer_id': 'nunique',
        'event_type': 'count',
        'severity': 'max'
    }).reset_index()
    
    # Find suspicious IPs (targeting multiple customers with high severity)
    suspicious_ips = ip_activity[
        (ip_activity['customer_id'] > 1) & 
        (ip_activity['severity'] > 5)
    ]
    
    # Generate alerts for cross-customer attacks
    alerts = []
    for _, ip_row in suspicious_ips.iterrows():
        ip = ip_row['source_ip']
        customers = events_df[events_df['source_ip'] == ip]['customer_name'].unique()
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'customer_id': 'multi',
            'customer_name': 'Multiple Customers',
            'source_ip': ip,
            'alert_type': 'cross_customer_attack',
            'description': f"IP {ip} targeting multiple customers: {', '.join(customers)}",
            'severity': 9  # High severity for cross-customer attacks
        }
        alerts.append(alert)
    
    # Save alerts to database
    if alerts:
        for alert in alerts:
            conn.execute('''INSERT INTO alerts 
                         (timestamp, customer_id, customer_name, source_ip, alert_type, description, severity)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (alert['timestamp'], alert['customer_id'], alert['customer_name'],
                      alert['source_ip'], alert['alert_type'], alert['description'], alert['severity']))
    
    conn.commit()
    conn.close()
    
    return alerts

if __name__ == "__main__":
    detect_anomalies()
    detect_cross_customer_attacks()