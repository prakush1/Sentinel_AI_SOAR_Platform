"""
Sentinel AI SOAR SOC - Security Data Generator
Generates synthetic security alerts, cases, and threat intelligence data
"""

import sqlite3
import pandas as pd
import numpy as np
from faker import Faker
import datetime
import random

fake = Faker()

DB_NAME = "sentinel_soc.db"
NUM_ALERTS = 2000
NUM_CASES = 300

SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
ALERT_STATUSES = ['New', 'In Progress', 'Resolved', 'Closed', 'False Positive']
CASE_STATUSES = ['Open', 'In Progress', 'Resolved', 'Closed']
CASE_PRIORITIES = ['Critical', 'High', 'Medium', 'Low']
SOURCES = ['Firewall', 'IDS/IPS', 'SIEM', 'EDR', 'Cloud Security', 'Email Security', 'NDR', 'IAM']
ALERT_TYPES = [
    'Suspicious Login Attempt',
    'Malware Detected',
    'Data Exfiltration',
    'Privilege Escalation',
    'Brute Force Attack',
    'Phishing Email',
    'Unauthorized Access',
    'DDoS Attack',
    'Ransomware Activity',
    'Insider Threat',
    'Lateral Movement',
    'Command & Control',
    'Data Breach',
    'Zero-Day Exploit',
    'Policy Violation'
]
ASSET_CLASSES = ['Workstation', 'Server', 'Database', 'Cloud Instance', 'Network Device', 'Mobile Device']
MITRE_TECHNIQUES = [
    'T1078 - Valid Accounts',
    'T1059 - Command and Scripting Interpreter',
    'T1003 - OS Credential Dumping',
    'T1087 - Account Discovery',
    'T1098 - Account Manipulation',
    'T1110 - Brute Force',
    'T1566 - Phishing',
    'T1190 - Exploit Public-Facing Application',
    'T1055 - Process Injection',
    'T1071 - Application Layer Protocol'
]

def generate_alert_data(num_alerts):
    """Generate synthetic security alert data"""
    alerts = []
    
    for i in range(num_alerts):
        # Time distribution - more recent alerts
        hours_ago = np.random.exponential(scale=48)
        timestamp = datetime.datetime.now() - datetime.timedelta(hours=hours_ago)
        
        # Severity distribution weighted toward medium/high
        severity = np.random.choice(SEVERITIES, p=[0.1, 0.25, 0.45, 0.2])
        
        # Status based on age
        if hours_ago < 2:
            status = 'New'
        elif hours_ago < 24:
            status = np.random.choice(['New', 'In Progress'], p=[0.3, 0.7])
        else:
            status = np.random.choice(ALERT_STATUSES, p=[0.05, 0.15, 0.5, 0.25, 0.05])
        
        alert_type = random.choice(ALERT_TYPES)
        source = random.choice(SOURCES)
        asset = random.choice(ASSET_CLASSES)
        
        # Risk score based on severity
        base_risk = {'Critical': 90, 'High': 75, 'Medium': 50, 'Low': 25}[severity]
        risk_score = min(100, max(0, base_risk + random.randint(-10, 10)))
        
        # MITRE ATT&CK mapping
        mitre_tech = random.choice(MITRE_TECHNIQUES) if random.random() > 0.3 else None
        
        alert = {
            'alert_id': f'ALT-{100000 + i}',
            'timestamp': timestamp,
            'alert_type': alert_type,
            'severity': severity,
            'status': status,
            'source': source,
            'asset_type': asset,
            'source_ip': fake.ipv4() if random.random() > 0.3 else None,
            'destination_ip': fake.ipv4() if random.random() > 0.5 else None,
            'user': fake.user_name() if random.random() > 0.4 else None,
            'risk_score': risk_score,
            'mitre_technique': mitre_tech,
            'description': f'{alert_type} detected on {asset} from {source}',
            'assigned_to': random.choice(['admin', 'analyst1', 'analyst2', None]) if status != 'New' else None,
            'false_positive': status == 'False Positive'
        }
        alerts.append(alert)
    
    return pd.DataFrame(alerts)

def generate_case_data(num_cases, alert_ids):
    """Generate synthetic security case data"""
    cases = []
    
    for i in range(num_cases):
        created_date = datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 90))
        
        priority = np.random.choice(CASE_PRIORITIES, p=[0.15, 0.3, 0.4, 0.15])
        
        # Status distribution
        if (datetime.datetime.now() - created_date).days < 3:
            status = np.random.choice(['Open', 'In Progress'], p=[0.7, 0.3])
        else:
            status = np.random.choice(CASE_STATUSES, p=[0.1, 0.2, 0.4, 0.3])
        
        # Related alerts
        num_related = random.randint(1, 20)
        related_alerts = random.sample(alert_ids, min(num_related, len(alert_ids)))
        
        case_type = random.choice([
            'Malware Investigation',
            'Insider Threat',
            'Data Breach',
            'Ransomware Response',
            'Phishing Campaign',
            'Unauthorized Access',
            'Compliance Violation',
            'APT Investigation'
        ])
        
        case = {
            'case_id': f'CASE-{200000 + i}',
            'title': f'{case_type} - {fake.company()}',
            'priority': priority,
            'status': status,
            'created_date': created_date,
            'assigned_to': random.choice(['admin', 'analyst1', 'analyst2', 'analyst3']),
            'case_type': case_type,
            'related_alerts': ','.join(related_alerts),
            'alert_count': len(related_alerts),
            'description': f'Investigation of {case_type.lower()} incident',
            'resolution': 'Resolved' if status == 'Closed' else None
        }
        cases.append(case)
    
    return pd.DataFrame(cases)

def initialize_database():
    """Generate and save security data to SQLite"""
    print(f"Generating {NUM_ALERTS} security alerts...")
    alerts_df = generate_alert_data(NUM_ALERTS)
    
    print(f"Generating {NUM_CASES} security cases...")
    alert_ids = alerts_df['alert_id'].tolist()
    cases_df = generate_case_data(NUM_CASES, alert_ids)
    
    # Ensure datetime columns
    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
    cases_df['created_date'] = pd.to_datetime(cases_df['created_date'])
    
    print(f"Saving to {DB_NAME}...")
    conn = sqlite3.connect(DB_NAME)
    alerts_df.to_sql("alerts", conn, if_exists="replace", index=False)
    cases_df.to_sql("cases", conn, if_exists="replace", index=False)
    conn.close()
    
    print("Database initialized successfully!")
    return alerts_df, cases_df

if __name__ == "__main__":
    initialize_database()
