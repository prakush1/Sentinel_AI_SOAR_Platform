"""
Sentinel AI SOAR SOC - Analytics Engine
Security Operations Center metrics and analytics
"""

import pandas as pd
import sqlalchemy
from sqlalchemy import create_engine
import datetime

DB_NAME = "sentinel_soc.db"

def get_engine(db_url=None):
    """Returns SQLAlchemy engine connection"""
    if not db_url:
        db_url = f"sqlite:///{DB_NAME}"
    return create_engine(db_url)

def init_audit_log(db_url=None):
    """Creates audit log table"""
    engine = get_engine(db_url)
    with engine.connect() as conn:
        conn.execute(sqlalchemy.text("""
            CREATE TABLE IF NOT EXISTS audit_log (
                LogID INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                User TEXT,
                Action TEXT,
                Details TEXT,
                Status TEXT
            )
        """))
        conn.commit()

def log_action(user, action, details, status="Success", db_url=None):
    """Records event to audit log"""
    init_audit_log(db_url)
    engine = get_engine(db_url)
    timestamp = pd.Timestamp.now().isoformat()
    
    with engine.connect() as conn:
        conn.execute(sqlalchemy.text("""
            INSERT INTO audit_log (Timestamp, User, Action, Details, Status)
            VALUES (:ts, :user, :action, :details, :status)
        """), {"ts": timestamp, "user": user, "action": action, "details": details, "status": status})
        conn.commit()

def get_audit_logs(limit=50, db_url=None):
    """Fetches recent audit logs"""
    init_audit_log(db_url)
    engine = get_engine(db_url)
    with engine.connect() as conn:
        return pd.read_sql(f"SELECT * FROM audit_log ORDER BY Timestamp DESC LIMIT {limit}", conn)

def get_soc_kpis(db_url=None):
    """Calculate SOC KPIs"""
    engine = get_engine(db_url)
    
    # Alert metrics
    alert_query = """
    SELECT 
        COUNT(*) as TotalAlerts,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as CriticalAlerts,
        SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as HighAlerts,
        SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END) as NewAlerts,
        SUM(CASE WHEN status IN ('Open', 'In Progress') THEN 1 ELSE 0 END) as OpenAlerts,
        AVG(risk_score) as AvgRiskScore,
        SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as FalsePositives
    FROM alerts
    WHERE timestamp >= datetime('now', '-24 hours')
    """
    
    # Case metrics
    case_query = """
    SELECT 
        COUNT(*) as TotalCases,
        SUM(CASE WHEN priority = 'Critical' THEN 1 ELSE 0 END) as CriticalCases,
        SUM(CASE WHEN status IN ('Open', 'In Progress') THEN 1 ELSE 0 END) as OpenCases,
        AVG(alert_count) as AvgAlertsPerCase
    FROM cases
    """
    
    with engine.connect() as conn:
        alert_kpis = pd.read_sql(alert_query, conn).iloc[0]
        case_kpis = pd.read_sql(case_query, conn).iloc[0]
    
    return {
        'TotalAlerts': int(alert_kpis['TotalAlerts']),
        'CriticalAlerts': int(alert_kpis['CriticalAlerts']),
        'HighAlerts': int(alert_kpis['HighAlerts']),
        'NewAlerts': int(alert_kpis['NewAlerts']),
        'OpenAlerts': int(alert_kpis['OpenAlerts']),
        'AvgRiskScore': round(alert_kpis['AvgRiskScore'], 1) if alert_kpis['AvgRiskScore'] else 0,
        'FalsePositives': int(alert_kpis['FalsePositives']),
        'TotalCases': int(case_kpis['TotalCases']),
        'CriticalCases': int(case_kpis['CriticalCases']),
        'OpenCases': int(case_kpis['OpenCases']),
        'AvgAlertsPerCase': round(case_kpis['AvgAlertsPerCase'], 1) if case_kpis['AvgAlertsPerCase'] else 0
    }

def get_alerts(limit=1000, severity=None, status=None, db_url=None):
    """Fetch alerts with optional filters"""
    engine = get_engine(db_url)
    
    where_clauses = []
    if severity:
        severity_list = ', '.join(["'" + s + "'" for s in severity])
        where_clauses.append(f"severity IN ({severity_list})")
    if status:
        status_list = ', '.join(["'" + s + "'" for s in status])
        where_clauses.append(f"status IN ({status_list})")
    
    where_str = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    
    query = f"""
    SELECT * FROM alerts 
    {where_str}
    ORDER BY timestamp DESC 
    LIMIT {limit}
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def get_cases(limit=500, priority=None, status=None, db_url=None):
    """Fetch cases with optional filters"""
    engine = get_engine(db_url)
    
    where_clauses = []
    if priority:
        priority_list = ', '.join(["'" + p + "'" for p in priority])
        where_clauses.append(f"priority IN ({priority_list})")
    if status:
        status_list = ', '.join(["'" + s + "'" for s in status])
        where_clauses.append(f"status IN ({status_list})")
    
    where_str = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    
    query = f"""
    SELECT * FROM cases 
    {where_str}
    ORDER BY created_date DESC 
    LIMIT {limit}
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def get_alert_trends(db_url=None, hours=24):
    """Get alert trends over time"""
    engine = get_engine(db_url)
    
    query = f"""
    SELECT 
        strftime('%Y-%m-%d %H:00', timestamp) as Hour,
        severity,
        COUNT(*) as Count
    FROM alerts
    WHERE timestamp >= datetime('now', '-{hours} hours')
    GROUP BY Hour, severity
    ORDER BY Hour
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def get_top_threats(db_url=None, limit=10):
    """Get top alert types by volume"""
    engine = get_engine(db_url)
    
    query = f"""
    SELECT 
        alert_type,
        severity,
        COUNT(*) as Count,
        AVG(risk_score) as AvgRisk
    FROM alerts
    WHERE timestamp >= datetime('now', '-24 hours')
    GROUP BY alert_type, severity
    ORDER BY Count DESC
    LIMIT {limit}
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def get_mitre_attack_coverage(db_url=None):
    """Get MITRE ATT&CK technique coverage"""
    engine = get_engine(db_url)
    
    query = """
    SELECT 
        mitre_technique,
        COUNT(*) as Count,
        AVG(risk_score) as AvgRisk
    FROM alerts
    WHERE mitre_technique IS NOT NULL
    AND timestamp >= datetime('now', '-7 days')
    GROUP BY mitre_technique
    ORDER BY Count DESC
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def get_source_breakdown(db_url=None):
    """Get alert breakdown by security source"""
    engine = get_engine(db_url)
    
    query = """
    SELECT 
        source,
        COUNT(*) as Total,
        SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as Critical,
        SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as High,
        AVG(risk_score) as AvgRiskScore
    FROM alerts
    WHERE timestamp >= datetime('now', '-24 hours')
    GROUP BY source
    ORDER BY Total DESC
    """
    
    with engine.connect() as conn:
        return pd.read_sql(query, conn)

def run_integrity_checks(db_url=None):
    """Run data integrity checks"""
    engine = get_engine(db_url)
    results = {}
    
    # Check 1: Alerts with high risk but low severity
    query_risk_mismatch = """
    SELECT * FROM alerts 
    WHERE risk_score > 80 AND severity IN ('Low', 'Medium')
    """
    
    # Check 2: Cases with no related alerts
    query_orphan_cases = """
    SELECT * FROM cases 
    WHERE related_alerts IS NULL OR related_alerts = ''
    """
    
    # Check 3: Old unresolved critical alerts
    query_stale_critical = """
    SELECT * FROM alerts 
    WHERE severity = 'Critical' 
    AND status IN ('New', 'In Progress')
    AND timestamp < datetime('now', '-4 hours')
    """
    
    with engine.connect() as conn:
        results['RiskSeverityMismatch'] = pd.read_sql(query_risk_mismatch, conn)
        results['OrphanCases'] = pd.read_sql(query_orphan_cases, conn)
        results['StaleCriticalAlerts'] = pd.read_sql(query_stale_critical, conn)
    
    return results

def execute_custom_query(query, db_url=None):
    """Safe execution of custom SQL queries"""
    blocked_keywords = ['drop', 'delete', 'update', 'insert', 'alter', 'create']
    
    if any(kw in query.lower() for kw in blocked_keywords):
        return pd.DataFrame({"Error": ["Read-only access: Write operations blocked for security"]})
    
    engine = get_engine(db_url)
    try:
        with engine.connect() as conn:
            return pd.read_sql(query, conn)
    except Exception as e:
        return pd.DataFrame({"Error": [str(e)]})
