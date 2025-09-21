# 🛡️ Shai - DevSecOps AI Assistant

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-red)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-demo%20ready-orange)

An AI-powered security monitoring and analysis platform that ingests, processes, and analyzes security logs from multiple sources to provide intelligent threat detection, automated response recommendations, and proactive security insights.

## 🌟 Key Features

- **🤖 AI-Powered Analysis**: Machine learning algorithms for intelligent threat detection and anomaly detection
- **🌍 Global Threat Visualization**: Interactive world map showing real-time attack patterns
- **⚡ Automated Response**: One-click containment of threats and automated playbook execution
- **💬 Natural Language Interface**: Chat-based interaction for security operations
- **🏢 Multi-Tenant Support**: Manage security for multiple organizations from a single dashboard
- **📊 Comprehensive Dashboard**: Real-time metrics, visualizations, and alert management

## 🏗️ Architecture Overview

```
Data Sources → Ingestion → Processing → Analysis → Response → Visualization
    ↑           (Kafka)    (Flink)    (AI/ML)   (Playbooks)  (Streamlit)
    └─────────────────────────────────────────────────────────────┘
                         Real-time Feedback Loop
```

## 🛠️ Technology Stack

- **Backend**: Python, FastAPI
- **Data Processing**: Apache Kafka, Apache Flink
- **AI/ML**: Scikit-learn, Isolation Forest, Transformer models
- **Database**: SQLite (demo), TimescaleDB & Neo4j (production-ready)
- **Frontend**: Streamlit, Plotly, D3.js
- **Infrastructure**: Docker, Kubernetes (production-ready)

## 📦 Installation & Setup

### Prerequisites

- Python 3.8+
- pip package manager
- Git

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/shai-devsecops-assistant.git
   cd shai-devsecops-assistant
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the demo**
   ```bash
   # Terminal 1 - Start log generation
   python generate_logs.py
   
   # Terminal 2 - Process logs (run after logs are generated)
   python ingest.py
   
   # Terminal 3 - Launch dashboard
   streamlit run dashboard.py
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:8501`

## 🚀 Usage Guide

### Demo Scenario

1. **Start the log generator** to simulate security events
2. **Run the ingestion process** to load events into the database
3. **Open the dashboard** to view real-time security monitoring
4. **Use the chat interface** to interact with Shai:
   - "show failed logins in the last hour"
   - "block 192.168.1.100"
   - "contain web-server-1"
   - "generate security report"

### Key Interactions

- **Global Threat Map**: View attack patterns worldwide
- **Multi-tenant Filter**: Switch between different customer organizations
- **AI Alerting**: See automated threat detections
- **Response Actions**: Contain threats with one click
- **Natural Language Queries**: Ask questions in plain English

## 📁 Project Structure

```
shai-devsecops-assistant/
├── config.py              # Configuration settings and constants
├── generate_logs.py       # Simulates security events from multiple sources
├── ingest.py             # Processes logs and loads them into database
├── model.py              # AI/ML analysis and anomaly detection
├── playbook.py           # Automated response actions and workflows
├── dashboard.py          # Main Streamlit dashboard application
├── requirements.txt      # Python dependencies
├── blocked_ips.json      # Storage for blocked IP addresses
├── contained_assets.json # Storage for contained assets
└── logs/                 # Directory for generated log files
```

## 🎯 Demo Instructions for Hackathon

### Pre-presentation Setup

1. Start all three services in separate terminals:
   ```bash
   # Terminal 1 - Log generation
   python generate_logs.py
   
   # Terminal 2 - Data processing (wait 30 seconds after Terminal 1)
   python ingest.py
   
   # Terminal 3 - Dashboard
   streamlit run dashboard.py
   ```

2. Open the dashboard at http://localhost:8501

3. Click "Refresh Data & Run Analysis" in the sidebar

### Demo Script

1. **Introduction**: "Shai is an AI-powered security assistant that helps teams monitor, analyze, and respond to threats."

2. **Show Global Threat Map**: "Here we see attacks happening in real-time across our customer organizations."

3. **Demonstrate Multi-tenancy**: "We can filter between different organizations like Acme Corp, Beta Bank, and Gamma Healthcare."

4. **AI Detection**: "Notice how Shai automatically detected these anomalous patterns using machine learning."

5. **Chat Interface**: "Let me ask Shai to show us recent failed logins..." (type "show failed logins")

6. **Automated Response**: "Now I'll contain this threat with a simple command..." (type "block 192.168.1.100")

7. **Highlight Efficiency**: "What would traditionally take security analysts hours now takes seconds with Shai."

## 🔮 Future Enhancements

- [ ] Integration with real security tools (Palo Alto, Splunk, etc.)
- [ ] Additional AI models for advanced threat detection
- [ ] Mobile application for on-the-go monitoring
- [ ] Advanced reporting and compliance features
- [ ] API for third-party integrations
- [ ] Real-time collaboration features for security teams

## 👥 Contributing

We welcome contributions to Shai! Please feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

For support, questions, or collaboration opportunities:

- Create an issue in this repository
- Email: 15asktt@gmail.com
- LinkedIn: http://linkedin.com/in/ansinitro

## 🎓 Acknowledgments

- Built for DataThon2025 (shai.pro case)
- Inspired by modern DevSecOps practices
- Utilizes open-source technologies and frameworks

---

**Shai - Transforming security operations from reactive to proactive through AI-powered automation.**