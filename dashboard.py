import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import json
import time
import os
from datetime import datetime, timedelta
from config import DB_PATH, CUSTOMERS, LOG_DIR
from model import detect_anomalies, detect_cross_customer_attacks
from playbook import block_ip, contain_asset, get_blocked_ips, get_contained_assets, init_response_files
from ingest import init_db

# Initialize database and response files before anything else
os.makedirs(LOG_DIR, exist_ok=True)
init_db()
init_response_files()

# Set page configuration
st.set_page_config(
    page_title="Shai DevSecOps AI Assistant",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'selected_customer' not in st.session_state:
    st.session_state.selected_customer = "all"
if 'initialized' not in st.session_state:
    st.session_state.initialized = True

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {font-size: 3rem; color: #1f77b4; padding-bottom: 10px;}
    .alert-card {border-left: 5px solid #ff4b4b; padding: 10px; margin: 5px 0;}
    .success-card {border-left: 5px solid #00cc96; padding: 10px; margin: 5px 0;}
    .blocked-ip {color: #ff4b4b; font-weight: bold;}
    .metric-card {background-color: #f0f2f6; padding: 15px; border-radius: 5px; margin: 5px 0;}
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<h1 class="main-header">🛡️ Shai DevSecOps AI Assistant</h1>', unsafe_allow_html=True)

# Sidebar for controls
with st.sidebar:
    st.header("Controls")
    
    # Customer filter
    customer_options = {**{"all": "All Customers"}, **{cid: c["name"] for cid, c in CUSTOMERS.items()}}
    selected_customer = st.selectbox(
        "Select Customer",
        options=list(customer_options.keys()),
        format_func=lambda x: customer_options[x],
        index=0
    )
    st.session_state.selected_customer = selected_customer
    
    # Time range filter
    time_range = st.selectbox(
        "Time Range",
        options=["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"],
        index=1
    )
    
    # Refresh data button
    if st.button("🔄 Refresh Data & Run Analysis"):
        # Run anomaly detection
        with st.spinner("Analyzing data for anomalies..."):
            detect_anomalies()
            detect_cross_customer_attacks()
        st.success("Analysis complete!")
        st.rerun()
    
    # Display blocked IPs and contained assets
    st.subheader("Response Status")
    blocked_ips = get_blocked_ips()
    contained_assets = get_contained_assets()
    
    st.write(f"**Blocked IPs:** {len(blocked_ips)}")
    for ip in blocked_ips[-3:]:  # Show last 3
        st.write(f"• `{ip['ip']}`")
    
    st.write(f"**Contained Assets:** {len(contained_assets)}")
    for asset in contained_assets[-3:]:  # Show last 3
        st.write(f"• `{asset['name']}`")
    
    # # Demo instructions
    # st.markdown("---")
    # st.subheader("Demo Instructions")
    # st.info("""
    # 1. Run log generator: `python generate_logs.py`
    # 2. Click 'Refresh Data' above
    # 3. View metrics and interact with charts
    # 4. Use chat commands to respond to threats
    # """)

# Helper function to get time filter
def get_time_filter(time_range_str):
    now = datetime.now()
    if time_range_str == "Last 1 hour":
        return (now - timedelta(hours=1)).isoformat()
    elif time_range_str == "Last 6 hours":
        return (now - timedelta(hours=6)).isoformat()
    elif time_range_str == "Last 24 hours":
        return (now - timedelta(hours=24)).isoformat()
    else:  # Last 7 days
        return (now - timedelta(days=7)).isoformat()

# Helper function to generate a simple threat report
def generate_threat_report():
    conn = sqlite3.connect(DB_PATH)
    
    # Get data for the last 24 hours
    one_day_ago = (datetime.now() - timedelta(days=1)).isoformat()
    
    # Event statistics
    events_by_type = pd.read_sql_query(
        "SELECT event_type, COUNT(*) as count FROM security_events WHERE timestamp > ? GROUP BY event_type",
        conn, params=[one_day_ago]
    )
    
    events_by_severity = pd.read_sql_query(
        "SELECT severity, COUNT(*) as count FROM security_events WHERE timestamp > ? GROUP BY severity",
        conn, params=[one_day_ago]
    )
    
    top_attackers = pd.read_sql_query(
        "SELECT source_ip, source_country, COUNT(*) as count FROM security_events WHERE timestamp > ? GROUP BY source_ip ORDER BY count DESC LIMIT 10",
        conn, params=[one_day_ago]
    )
    
    conn.close()
    
    # Generate report text
    report = f"Threat Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
    report += "Event Summary (Last 24 hours):\n"
    
    for _, row in events_by_type.iterrows():
        report += f"- {row['event_type']}: {row['count']} events\n"
    
    report += f"\nTop Attackers:\n"
    for _, row in top_attackers.iterrows():
        report += f"- {row['source_ip']} ({row['source_country']}): {row['count']} events\n"
    
    return report

# Helper function to analyze an IP address
def analyze_ip_address(ip_address):
    conn = sqlite3.connect(DB_PATH)
    
    # Get events from this IP
    ip_events = pd.read_sql_query(
        "SELECT * FROM security_events WHERE source_ip = ? ORDER BY timestamp DESC",
        conn, params=[ip_address]
    )
    
    conn.close()
    
    if ip_events.empty:
        return None
    
    # Calculate threat score (simple algorithm for demo)
    severity_score = ip_events['severity'].mean()
    frequency_score = min(10, len(ip_events) / 5)  # Cap at 10
    diversity_score = min(10, ip_events['customer_id'].nunique() * 2)  # Cap at 10
    
    threat_score = (severity_score + frequency_score + diversity_score) / 3
    
    return {
        'events': ip_events,
        'threat_score': threat_score,
        'targeted_customers': ip_events['customer_id'].nunique(),
        'attack_types': ip_events['event_type'].nunique(),
        'first_seen': ip_events['timestamp'].min(),
        'last_seen': ip_events['timestamp'].max()
    }

# Connect to database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if tables exist
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
events_table_exists = cursor.fetchone() is not None

cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
alerts_table_exists = cursor.fetchone() is not None

# Main dashboard layout
if events_table_exists:
    # Get time filter
    time_filter = get_time_filter(time_range)
    
    # Build query based on filters
    query = "SELECT * FROM security_events WHERE timestamp > ?"
    params = [time_filter]
    
    if st.session_state.selected_customer != "all":
        query += " AND customer_id = ?"
        params.append(st.session_state.selected_customer)
    
    # Get events data
    events_df = pd.read_sql_query(query, conn, params=params)
    
    # Get alerts data
    if alerts_table_exists:
        alerts_query = "SELECT * FROM alerts WHERE timestamp > ? ORDER BY timestamp DESC"
        alerts_df = pd.read_sql_query(alerts_query, conn, params=[time_filter])
    else:
        alerts_df = pd.DataFrame()
    
    # Top metrics row
    st.subheader("📊 Security Metrics Dashboard")
    
    metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
    
    with metric_col1:
        total_events = len(events_df)
        st.metric("Total Events", total_events)
    
    with metric_col2:
        unique_attackers = events_df['source_ip'].nunique() if not events_df.empty else 0
        st.metric("Unique Attackers", unique_attackers)
    
    with metric_col3:
        open_alerts = len(alerts_df[alerts_df['status'] == 'open']) if not alerts_df.empty else 0
        st.metric("Open Alerts", open_alerts)
    
    with metric_col4:
        avg_severity = events_df['severity'].mean().round(2) if not events_df.empty else 0
        st.metric("Avg. Severity", avg_severity)
    
    # First row of charts
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.subheader("🌍 Attack Origins")
        if not events_df.empty:
            # Count events by source country
            country_counts = events_df['source_country'].value_counts().reset_index()
            country_counts.columns = ['country', 'count']
            
            # Create choropleth map
            fig = px.choropleth(
                country_counts,
                locations='country',
                locationmode='country names',
                color='count',
                hover_name='country',
                color_continuous_scale='reds',
                title='Attacks by Country'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events to display on map.")
    
    with chart_col2:
        st.subheader("📈 Events Over Time")
        if not events_df.empty:
            # Convert timestamp to datetime and extract hour
            events_df['hour'] = pd.to_datetime(events_df['timestamp']).dt.floor('H')
            hourly_counts = events_df.groupby('hour').size().reset_index(name='count')
            
            # Create line chart
            fig = px.line(
                hourly_counts, 
                x='hour', 
                y='count',
                title='Events by Hour'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events to display over time.")
    
    # Second row of charts
    chart_col3, chart_col4 = st.columns(2)
    
    with chart_col3:
        st.subheader("🔢 Event Types")
        if not events_df.empty:
            # Count events by type
            type_counts = events_df['event_type'].value_counts().reset_index()
            type_counts.columns = ['event_type', 'count']
            
            # Create bar chart
            fig = px.bar(
                type_counts,
                x='event_type',
                y='count',
                color='count',
                color_continuous_scale='reds',
                title='Events by Type'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events to display by type.")
    
    with chart_col4:
        st.subheader("⚠️ Severity Distribution")
        if not events_df.empty:
            # Create severity distribution pie chart
            severity_counts = events_df['severity'].value_counts().reset_index()
            severity_counts.columns = ['severity', 'count']
            
            fig = px.pie(
                severity_counts,
                values='count',
                names='severity',
                title='Events by Severity Level'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No events to display by severity.")
    
    # Third row - Alerts and Top Attackers
    chart_col5, chart_col6 = st.columns(2)
    
    with chart_col5:
        st.subheader("🚨 Recent Alerts")
        if not alerts_df.empty:
            # Display recent alerts
            for _, alert in alerts_df.head(5).iterrows():
                severity_color = "#ff4b4b" if alert['severity'] > 7 else "#ffa500"
                st.markdown(f"""
                <div class="alert-card">
                    <strong>{alert['customer_name']}</strong> - {alert['description']}<br>
                    <small>Severity: <span style="color: {severity_color}">{alert['severity']}/10</span> • {alert['timestamp']}</small>
                </div>
                """, unsafe_allow_html=True)
            
            if len(alerts_df) > 5:
                st.write(f"... and {len(alerts_df) - 5} more alerts")
        else:
            st.info("No recent alerts. Everything looks good!")
    
    with chart_col6:
        st.subheader("🎯 Top Attackers")
        if not events_df.empty:
            # Get top attacking IPs
            top_attackers = events_df['source_ip'].value_counts().head(10).reset_index()
            top_attackers.columns = ['ip', 'count']
            
            # Add country information
            ip_countries = events_df[['source_ip', 'source_country']].drop_duplicates()
            top_attackers = top_attackers.merge(ip_countries, left_on='ip', right_on='source_ip', how='left')
            
            # Create bar chart
            fig = px.bar(
                top_attackers,
                x='count',
                y='ip',
                color='source_country',
                orientation='h',
                title='Top 10 Attacking IPs',
                hover_data=['source_country']
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacker data available.")

else:
    st.warning("No security events data available. Please run the log generator first.")

conn.close()

# NLP Chat Interface
st.subheader("💬 Security Assistant - Advanced Commands")

# Command suggestions
st.info("""
**Try these commands:**
- `show failed logins` - Display recent login attempts
- `block [IP]` - Block an IP across all systems
- `contain [asset]` - Contain a compromised asset
- `show alerts` - Display current security alerts
- `analyze [IP]` - Deep analysis of an IP address
- `threat report` - Generate threat intelligence report
- `system status` - Show system health metrics
- `help` - Show all available commands
""")

user_input = st.text_input("Ask Shai to perform an action or show information:", 
                          placeholder="e.g., 'analyze 192.168.1.100' or 'threat report'")

if user_input:
    user_input = user_input.lower()
    
    if "show failed logins" in user_input:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            failed_logins = pd.read_sql_query(
                "SELECT * FROM security_events WHERE event_type = 'ssh_brute_force' ORDER BY timestamp DESC LIMIT 10",
                conn
            )
            if not failed_logins.empty:
                st.dataframe(failed_logins[['timestamp', 'source_ip', 'customer_name', 'severity']])
            else:
                st.success("No failed login attempts found in recent events.")
        else:
            st.info("No data available yet. Please run the log generator.")
        conn.close()
    
    elif "block" in user_input:
        # Extract IP address from command
        words = user_input.split()
        ip_to_block = None
        for word in words:
            if '.' in word and word.count('.') == 3:
                ip_to_block = word
                break
        
        if ip_to_block:
            result = block_ip(ip_to_block, f"Blocked via chat command: {user_input}")
            st.success(result)
            st.rerun()
        else:
            st.error("Could not extract a valid IP address from your command.")
    
    elif "contain" in user_input:
        # Extract asset name from command
        words = user_input.split()
        if len(words) > 1:
            asset_name = words[1]
            result = contain_asset(asset_name, f"Contained via chat command: {user_input}")
            st.success(result)
            st.rerun()
        else:
            st.error("Please specify an asset to contain.")
    
    elif "show events" in user_input:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            events = pd.read_sql_query(
                "SELECT timestamp, customer_name, source_ip, event_type, severity FROM security_events ORDER BY timestamp DESC LIMIT 20",
                conn
            )
            st.dataframe(events)
        else:
            st.info("No data available yet. Please run the log generator.")
        conn.close()
    
    elif "show alerts" in user_input:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            alerts = pd.read_sql_query(
                "SELECT timestamp, customer_name, source_ip, alert_type, description, severity FROM alerts ORDER BY timestamp DESC LIMIT 15",
                conn
            )
            if not alerts.empty:
                st.dataframe(alerts)
            else:
                st.success("No active alerts. System is secure.")
        else:
            st.info("No alerts data available.")
        conn.close()
    
    elif "analyze" in user_input:
        # Extract IP address from command
        words = user_input.split()
        ip_to_analyze = None
        for word in words:
            if '.' in word and word.count('.') == 3:
                ip_to_analyze = word
                break
        
        if ip_to_analyze:
            conn = sqlite3.connect(DB_PATH)
            
            # Get events from this IP
            ip_events = pd.read_sql_query(
                "SELECT * FROM security_events WHERE source_ip = ? ORDER BY timestamp DESC",
                conn, params=[ip_to_analyze]
            )
            
            if not ip_events.empty:
                st.subheader(f"🤖 AI Analysis of IP: {ip_to_analyze}")
                
                # Display summary metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Events", len(ip_events))
                with col2:
                    st.metric("Targeted Customers", ip_events['customer_id'].nunique())
                with col3:
                    st.metric("Attack Types", ip_events['event_type'].nunique())
                with col4:
                    st.metric("Avg. Severity", ip_events['severity'].mean().round(1))
                
                # Show events from this IP
                st.write("**Recent activity:**")
                st.dataframe(ip_events[['timestamp', 'customer_name', 'event_type', 'severity']].head(10))
                
                # AI-generated threat assessment
                threat_score = min(10, int(ip_events['severity'].mean() + ip_events['customer_id'].nunique()))
                st.write(f"**AI Threat Assessment:** {threat_score}/10 risk level")
                
                if threat_score > 7:
                    st.error("🚨 High threat IP - Recommend immediate blocking")
                elif threat_score > 4:
                    st.warning("⚠️ Moderate threat IP - Recommend monitoring")
                else:
                    st.success("✅ Low threat IP - Normal activity")
                    
            else:
                st.info(f"No events found for IP: {ip_to_analyze}")
            
            conn.close()
        else:
            st.error("Please specify a valid IP address to analyze.")
    
    elif "threat report" in user_input:
        conn = sqlite3.connect(DB_PATH)
        
        # Get data for report
        events_count = pd.read_sql_query(
            "SELECT COUNT(*) as count FROM security_events WHERE timestamp > datetime('now', '-1 day')",
            conn
        )['count'].iloc[0]
        
        alerts_count = pd.read_sql_query(
            "SELECT COUNT(*) as count FROM alerts WHERE timestamp > datetime('now', '-1 day')",
            conn
        )['count'].iloc[0]
        
        top_threats = pd.read_sql_query(
            "SELECT event_type, COUNT(*) as count FROM security_events WHERE timestamp > datetime('now', '-1 day') GROUP BY event_type ORDER BY count DESC LIMIT 5",
            conn
        )
        
        conn.close()
        
        # Generate report
        st.subheader("📊 Daily Threat Intelligence Report")
        st.write(f"**Report Period:** Last 24 hours")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Events", events_count)
        with col2:
            st.metric("Alerts Generated", alerts_count)
        
        st.write("**Top Threat Types:**")
        for _, threat in top_threats.iterrows():
            st.write(f"- {threat['event_type']}: {threat['count']} events")
        
        # AI-generated insights
        st.write("**AI Security Insights:**")
        if events_count > 100:
            st.warning("⚠️ Elevated threat activity detected. Consider increasing monitoring.")
        else:
            st.success("✅ Normal threat levels. No significant anomalies detected.")
        
        st.download_button(
            label="Download PDF Report",
            data="Simulated PDF report content - in production would generate actual PDF",
            file_name="threat_report.pdf",
            mime="application/pdf"
        )
    
    elif "system status" in user_input:
        conn = sqlite3.connect(DB_PATH)
        
        # Get system metrics
        events_table_exists = pd.read_sql_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'",
            conn
        )
        
        if not events_table_exists.empty:
            event_count = pd.read_sql_query(
                "SELECT COUNT(*) as count FROM security_events",
                conn
            )['count'].iloc[0]
            
            latest_event = pd.read_sql_query(
                "SELECT timestamp FROM security_events ORDER BY timestamp DESC LIMIT 1",
                conn
            )
            
            if not latest_event.empty:
                latest_time = pd.to_datetime(latest_event['timestamp'].iloc[0])
                time_diff = (datetime.now() - latest_time).total_seconds() / 60  # minutes
                
                st.subheader("🖥️ System Status")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Events", event_count)
                with col2:
                    st.metric("Latest Event", f"{time_diff:.1f} min ago")
                with col3:
                    st.metric("Database", "✅ Operational")
                
                # Status indicators
                if time_diff < 5:
                    st.success("✅ Real-time data processing: Active")
                else:
                    st.error("❌ Real-time data processing: Delayed")
                
                st.success("✅ AI Analysis Engine: Operational")
                st.success("✅ Response System: Ready")
                
            else:
                st.info("System initialized but no events processed yet.")
        else:
            st.error("Database not properly initialized. Please run the log generator.")
        
        conn.close()
    
    elif "help" in user_input:
        st.subheader("🆘 Shai Security Assistant - Command Reference")
        
        st.write("""
        **Monitoring Commands:**
        - `show events` - Display recent security events
        - `show alerts` - View current security alerts
        - `show failed logins` - Show authentication failures
        - `system status` - Check system health
        
        **Investigation Commands:**
        - `analyze [IP]` - Deep analysis of an IP address
        - `threat report` - Generate threat intelligence report
        
        **Response Commands:**
        - `block [IP]` - Block an IP across all systems
        - `contain [asset]` - Contain a compromised asset
        
        **Example:**
        - `analyze 192.168.1.100`
        - `block 104.16.123.45`
        - `contain web-server-1`
        - `threat report`
        """)
    
    else:
        st.warning("""
        I didn't understand that command. Try one of these:
        - `show events` - View security events
        - `analyze [IP]` - Analyze an IP address
        - `block [IP]` - Block an IP
        - `threat report` - Generate report
        - `help` - Show all commands
        """)
# Footer
st.markdown("---")
st.markdown("**Shai DevSecOps AI Assistant** - Built for the Hackathon Demo | Real-time Security Monitoring")