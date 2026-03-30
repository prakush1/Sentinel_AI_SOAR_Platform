# 🛡️ Sentinel AI - SOAR SOC Platform

**Security Orchestration, Automation, and Response - Security Operations Center Dashboard**

Designed by **Prakush Shende**

## Overview

Sentinel AI SOAR SOC is an enterprise-grade Security Operations Center dashboard built entirely with Streamlit. It provides real-time security monitoring, AI-powered threat detection, case management, and MITRE ATT&CK framework integration.

## Features

### 🎯 Core Capabilities
- **SOC Dashboard** - Real-time KPIs, alert trends, and threat visualization
- **Alert Queue** - Intelligent alert management with filtering and triage
- **Case Management** - Incident tracking and investigation workflows
- **AI Threat Intelligence** - ML-powered anomaly detection and threat prediction
- **MITRE ATT&CK Mapping** - Threat intelligence framework integration
- **Emergency Kill Switch** - Instant automation halt capability

### 🤖 AI/ML Features
- **Anomaly Detection** - Isolation Forest algorithm for detecting unusual patterns
- **Threat Prediction** - Random Forest classifier for risk scoring
- **Risk Scoring** - Dynamic risk assessment based on multiple factors

### 📊 Analytics
- 24-hour alert trends
- Severity distribution analysis
- Source breakdown visualization
- MITRE ATT&CK technique coverage
- False positive tracking

## Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | SOC Administrator |
| `analyst` | `analyst123` | Security Analyst |
| `viewer` | `viewer123` | Read-Only Analyst |

## Deployment

### Streamlit Cloud (Recommended)
1. Push this repository to GitHub
2. Connect to [Streamlit Cloud](https://streamlit.io/cloud)
3. Deploy with one click

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

## Architecture

This is a **Streamlit-only application** - no separate frontend/backend:

```
app.py              # Main Streamlit application
analytics_engine.py # SOC metrics and database operations
ml_predictor.py     # Machine learning models
data_generator.py   # Synthetic security data generation
requirements.txt    # Python dependencies
```

### Data Storage
- **SQLite** database for alerts, cases, and audit logs
- **Pre-trained ML models** (pickle files) for threat detection
- **In-memory** analytics for real-time dashboards

## Tech Stack

- **Streamlit** - Web application framework
- **Pandas** - Data manipulation
- **Plotly** - Interactive visualizations
- **SQLAlchemy** - Database ORM
- **Scikit-learn** - Machine learning
- **Faker** - Synthetic data generation

## Security Features

- ✅ Authentication with role-based access
- ✅ Audit logging for all actions
- ✅ Emergency kill switch
- ✅ Data integrity checks
- ✅ Read-only SQL queries (write protection)
- ✅ Session management

## Pages

1. **SOC Dashboard** - Executive overview with KPIs and trends
2. **Alert Queue** - Alert management and triage
3. **Case Management** - Incident investigation workflows
4. **AI Threat Intel** - ML-powered threat detection
5. **MITRE ATT&CK** - Threat framework mapping
6. **SOC Settings** - Integrations, users, and system checks

## Generated Data

The application generates synthetic security data:
- **2,000 alerts** with various severities and types
- **300 cases** linked to alerts
- **MITRE ATT&CK techniques** mapped to alerts
- **24-hour rolling** alert history

## License

© 2026 Sentinel AI. All rights reserved.

Designed and developed by **Prakush Shende**
