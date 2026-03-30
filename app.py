"""
Sentinel AI SOAR SOC - Security Operations Center Dashboard
Streamlit Application for Enterprise Security Management
Designed by Prakush Shende
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import analytics_engine as analytics
import ml_predictor
import data_generator
import time
import os

# Page Config
st.set_page_config(
    page_title="Sentinel AI - SOAR SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database on First Run
DB_FILE = "sentinel_soc.db"
if not os.path.exists(DB_FILE):
    with st.spinner("🚀 Initializing Security Database..."):
        data_generator.initialize_database()
        ml_predictor.train_threat_model()
        ml_predictor.train_anomaly_model()

# Authentication
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("""
    <style>
    .auth-container {
        max-width: 450px;
        margin: 0 auto;
        padding: 3rem;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-radius: 15px;
        border: 1px solid #334155;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 2rem 0;">
            <h1 style="font-size: 3rem; margin-bottom: 0;">🛡️</h1>
            <h1>Sentinel AI</h1>
            <p style="color: #94a3b8; font-size: 1.1rem;">SOAR Security Operations Center</p>
            <p style="color: #3b82f6; font-size: 0.9rem; font-weight: 600;">Designed by Prakush Shende</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.container():
            username = st.text_input("👤 Username", placeholder="Enter username")
            password = st.text_input("🔒 Password", type="password", placeholder="Enter password")
            
            if st.button("🔐 Secure Login", use_container_width=True, type="primary"):
                if (username == "admin" and password == "admin123") or \
                   (username == "analyst" and password == "analyst123") or \
                   (username == "viewer" and password == "viewer123"):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    analytics.log_action(username, "Login", "User authenticated successfully", "Success")
                    st.success("✅ Authentication Successful!")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("❌ Invalid Credentials")
        
        st.markdown("""
        <div style="background: #1e293b; padding: 1.5rem; border-radius: 10px; margin-top: 2rem; border: 1px solid #334155;">
            <p style="margin: 0 0 0.5rem 0; color: #94a3b8; font-size: 0.9rem;"><strong>🔑 Demo Credentials:</strong></p>
            <p style="margin: 0; color: #64748b; font-size: 0.8rem;"><code>admin</code> / <code>admin123</code> (Administrator)</p>
            <p style="margin: 0; color: #64748b; font-size: 0.8rem;"><code>analyst</code> / <code>analyst123</code> (Analyst)</p>
            <p style="margin: 0; color: #64748b; font-size: 0.8rem;"><code>viewer</code> / <code>viewer123</code> (Read-Only)</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.stop()

# Sidebar
st.sidebar.title("🛡️ Sentinel AI")
st.sidebar.caption("SOAR SOC Platform")
st.sidebar.markdown("---")

# Emergency Kill Switch
with st.sidebar.expander("🚨 EMERGENCY KILL SWITCH", expanded=False):
    st.markdown("<p style='color: #ef4444; font-size: 0.8rem;'>⚠️ Halts all automation</p>", unsafe_allow_html=True)
    if st.button("🛑 ACTIVATE KILL SWITCH", type="primary", use_container_width=True):
        st.session_state.confirm_kill = True
    
    if st.session_state.get('confirm_kill'):
        st.warning("⚠️ Confirm system halt?")
        c1, c2 = st.columns(2)
        if c1.button("✅ HALT", type="primary"):
            analytics.log_action(st.session_state.username, "Emergency Stop", "Kill switch activated", "CRITICAL")
            st.error("🛑 SYSTEM HALTED - MANUAL RESTART REQUIRED")
            st.stop()
        if c2.button("❌ Cancel"):
            st.session_state.confirm_kill = False
            st.rerun()

st.sidebar.markdown("---")

# User Info
st.sidebar.markdown(f"**👤 User:** `{st.session_state.username}`")
if st.sidebar.button("🚪 Logout", use_container_width=True):
    analytics.log_action(st.session_state.username, "Logout", "User logged out", "Success")
    st.session_state.authenticated = False
    st.rerun()

st.sidebar.markdown("---")

# Navigation
page = st.sidebar.radio("📍 Navigation", [
    "📊 SOC Dashboard",
    "🚨 Alert Queue",
    "📁 Case Management", 
    "🤖 AI Threat Intel",
    "🎯 MITRE ATT&CK",
    "⚙️ SOC Settings"
])

st.sidebar.markdown("---")
st.sidebar.caption("© 2026 Sentinel AI")
st.sidebar.caption("Designed by Prakush Shende")

# Main Content
if page == "📊 SOC Dashboard":
    st.title("🛡️ Security Operations Center Dashboard")
    
    # KPIs
    kpis = analytics.get_soc_kpis()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🚨 24h Alerts", f"{kpis['TotalAlerts']:,}", f"+{kpis['NewAlerts']} new")
    with col2:
        st.metric("🔴 Critical", kpis['CriticalAlerts'], delta=None, delta_color="inverse")
    with col3:
        st.metric("📁 Open Cases", kpis['OpenCases'])
    with col4:
        st.metric("⚡ Avg Risk", f"{kpis['AvgRiskScore']}/100")
    
    # Second row KPIs
    col5, col6, col7, col8 = st.columns(4)
    with col5:
        st.metric("🟠 High Alerts", kpis['HighAlerts'])
    with col6:
        st.metric("🔍 In Progress", kpis['OpenAlerts'])
    with col7:
        st.metric("⚠️ False Positives", kpis['FalsePositives'])
    with col8:
        st.metric("📊 Alerts/Case", kpis['AvgAlertsPerCase'])
    
    st.markdown("---")
    
    # Charts Row 1
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("📈 Alert Severity Distribution")
        trends = analytics.get_alert_trends(hours=24)
        if not trends.empty:
            fig = px.bar(trends, x='Hour', y='Count', color='severity', 
                        title="Alerts by Hour and Severity",
                        template="plotly_dark", barmode='stack')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert data available")
    
    with col_right:
        st.subheader("🔥 Top Threats (24h)")
        threats = analytics.get_top_threats(limit=10)
        if not threats.empty:
            fig = px.bar(threats, x='alert_type', y='Count', color='severity',
                        title="Top Alert Types",
                        template="plotly_dark")
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data available")
    
    # Charts Row 2
    col_left2, col_right2 = st.columns(2)
    
    with col_left2:
        st.subheader("📡 Alert Sources")
        sources = analytics.get_source_breakdown()
        if not sources.empty:
            fig = px.pie(sources, values='Total', names='source', 
                        title="Alerts by Security Source",
                        template="plotly_dark", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
    
    with col_right2:
        st.subheader("🎯 MITRE ATT&CK Coverage")
        mitre = analytics.get_mitre_attack_coverage()
        if not mitre.empty:
            fig = px.bar(mitre, x='mitre_technique', y='Count',
                        title="Detected Techniques (7 days)",
                        template="plotly_dark")
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

elif page == "🚨 Alert Queue":
    st.title("🚨 Alert Queue Management")
    
    # Filters
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity_filter = st.multiselect("Severity", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    with col2:
        status_filter = st.multiselect("Status", ['New', 'In Progress', 'Resolved', 'Closed', 'False Positive'], default=['New', 'In Progress'])
    with col3:
        source_filter = st.multiselect("Source", ['Firewall', 'IDS/IPS', 'SIEM', 'EDR', 'Cloud Security', 'Email Security', 'NDR', 'IAM'])
    with col4:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    # Fetch alerts
    alerts_df = analytics.get_alerts(limit=1000, severity=severity_filter if severity_filter else None, 
                                     status=status_filter if status_filter else None)
    
    # Apply source filter
    if source_filter:
        alerts_df = alerts_df[alerts_df['source'].isin(source_filter)]
    
    st.markdown(f"**Showing {len(alerts_df)} alerts**")
    
    # Display with color coding
    st.dataframe(
        alerts_df[['alert_id', 'timestamp', 'alert_type', 'severity', 'status', 'source', 'risk_score', 'assigned_to']],
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100),
            "severity": st.column_config.TextColumn("Severity"),
            "timestamp": st.column_config.DatetimeColumn("Time", format="MMM DD, HH:mm")
        },
        use_container_width=True,
        hide_index=True
    )
    
    # Alert Detail View
    if not alerts_df.empty:
        selected = st.selectbox("Select Alert for Details", alerts_df['alert_id'].tolist())
        if selected:
            alert = alerts_df[alerts_df['alert_id'] == selected].iloc[0]
            with st.expander("🔍 Alert Details", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Type:** {alert['alert_type']}")
                    st.markdown(f"**Severity:** {alert['severity']}")
                    st.markdown(f"**Source:** {alert['source']}")
                    st.markdown(f"**Asset:** {alert['asset_type']}")
                with col2:
                    st.markdown(f"**Risk Score:** {alert['risk_score']}/100")
                    st.markdown(f"**User:** {alert['user'] or 'N/A'}")
                    st.markdown(f"**MITRE:** {alert['mitre_technique'] or 'N/A'}")
                st.markdown(f"**Description:** {alert['description']}")
                
                # Actions
                col_a1, col_a2, col_a3 = st.columns(3)
                with col_a1:
                    if st.button("✅ Mark Resolved", key=f"resolve_{selected}"):
                        st.success("Alert marked as resolved!")
                with col_a2:
                    if st.button("📁 Create Case", key=f"case_{selected}"):
                        st.info("Case creation dialog would open")
                with col_a3:
                    if st.button("🚫 False Positive", key=f"fp_{selected}"):
                        st.warning("Marked as false positive")

elif page == "📁 Case Management":
    st.title("📁 Incident Case Management")
    
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        priority_filter = st.multiselect("Priority", ['Critical', 'High', 'Medium', 'Low'], default=['Critical', 'High'])
    with col2:
        case_status_filter = st.multiselect("Status", ['Open', 'In Progress', 'Resolved', 'Closed'])
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("➕ New Case", use_container_width=True):
            st.info("Case creation form would open")
    
    cases_df = analytics.get_cases(limit=500, priority=priority_filter if priority_filter else None,
                                   status=case_status_filter if case_status_filter else None)
    
    st.markdown(f"**{len(cases_df)} cases found**")
    
    st.dataframe(
        cases_df[['case_id', 'title', 'priority', 'status', 'case_type', 'assigned_to', 'alert_count', 'created_date']],
        column_config={
            "priority": st.column_config.TextColumn("Priority"),
            "alert_count": st.column_config.NumberColumn("Alerts"),
            "created_date": st.column_config.DatetimeColumn("Created", format="MMM DD, YYYY")
        },
        use_container_width=True,
        hide_index=True
    )

elif page == "🤖 AI Threat Intel":
    st.title("🤖 AI-Powered Threat Intelligence")
    
    st.markdown("### Machine Learning Insights")
    
    # ML Insights
    insights = ml_predictor.get_ml_insights()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📊 Analyzed", insights['total_analyzed'])
    with col2:
        st.metric("🔴 High Risk", insights['high_risk_predicted'])
    with col3:
        st.metric("⚡ Anomalies", insights['anomalies_detected'])
    with col4:
        st.metric("🎯 Confidence", f"{insights['model_confidence']*100:.0f}%")
    
    st.markdown("---")
    
    # Anomaly Detection
    st.subheader("🔍 Anomaly Detection")
    
    alerts_df = analytics.get_alerts(limit=500)
    if not alerts_df.empty:
        anomalies = ml_predictor.detect_anomalies(alerts_df)
        anomaly_alerts = alerts_df[anomalies]
        
        if not anomaly_alerts.empty:
            st.warning(f"⚠️ {len(anomaly_alerts)} anomalous alerts detected!")
            st.dataframe(
                anomaly_alerts[['alert_id', 'alert_type', 'severity', 'source', 'risk_score']],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success("✅ No anomalies detected")
    
    # Threat Predictions
    st.subheader("🎯 Threat Predictions")
    
    if not alerts_df.empty:
        alerts_df['threat_prob'] = ml_predictor.predict_threat_probability(alerts_df)
        high_risk = alerts_df[alerts_df['threat_prob'] > 0.7].sort_values('threat_prob', ascending=False)
        
        if not high_risk.empty:
            st.dataframe(
                high_risk[['alert_id', 'alert_type', 'severity', 'threat_prob']],
                column_config={
                    "threat_prob": st.column_config.ProgressColumn(
                        "Threat Probability",
                        format="%.0f%%",
                        min_value=0,
                        max_value=1
                    )
                },
                use_container_width=True,
                hide_index=True
            )

elif page == "🎯 MITRE ATT&CK":
    st.title("🎯 MITRE ATT&CK Framework")
    
    st.markdown("### Threat Intelligence Mapping")
    
    mitre_data = analytics.get_mitre_attack_coverage()
    if not mitre_data.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(mitre_data, x='mitre_technique', y='Count', 
                        color='AvgRisk',
                        title="Technique Frequency vs Risk",
                        template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.scatter(mitre_data, x='Count', y='AvgRisk', 
                           size='Count', text='mitre_technique',
                           title="Risk vs Frequency Analysis",
                           template="plotly_dark")
            st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Technique Details")
        st.dataframe(mitre_data, use_container_width=True, hide_index=True)
    else:
        st.info("No MITRE ATT&CK data available")

elif page == "⚙️ SOC Settings":
    st.title("⚙️ SOC Configuration")
    
    tab1, tab2, tab3 = st.tabs(["🔌 Integrations", "👥 Users", "🔍 Integrity Checks"])
    
    with tab1:
        st.subheader("Security Integrations")
        integrations = [
            ("🔥 Firewall", "Connected ✅", "green"),
            ("🛡️ IDS/IPS", "Connected ✅", "green"),
            ("📊 SIEM", "Connected ✅", "green"),
            ("💻 EDR", "Connected ✅", "green"),
            ("☁️ Cloud Security", "Connected ✅", "green"),
            ("📧 Email Security", "Warning ⚠️", "orange"),
            ("🌐 NDR", "Connected ✅", "green"),
            ("🔑 IAM", "Connected ✅", "green"),
        ]
        
        for name, status, color in integrations:
            col1, col2 = st.columns([3, 1])
            col1.write(name)
            col2.markdown(f"<span style='color: {color};'>{status}</span>", unsafe_allow_html=True)
    
    with tab2:
        st.subheader("User Management")
        users = [
            {"username": "admin", "role": "SOC Administrator", "status": "🟢 Active"},
            {"username": "analyst", "role": "Security Analyst", "status": "🟢 Active"},
            {"username": "viewer", "role": "Read-Only Analyst", "status": "🟢 Active"},
        ]
        st.table(users)
    
    with tab3:
        st.subheader("🛡️ Data Integrity Checks")
        
        if st.button("Run Integrity Scan", type="primary"):
            with st.spinner("Running checks..."):
                results = analytics.run_integrity_checks()
                
                # Check 1
                st.markdown("#### 1. Risk-Severity Mismatches")
                if not results['RiskSeverityMismatch'].empty:
                    st.error(f"Found {len(results['RiskSeverityMismatch'])} mismatches!")
                    st.dataframe(results['RiskSeverityMismatch'])
                else:
                    st.success("✅ No mismatches found")
                
                # Check 2
                st.markdown("#### 2. Orphan Cases")
                if not results['OrphanCases'].empty:
                    st.error(f"Found {len(results['OrphanCases'])} orphan cases!")
                else:
                    st.success("✅ All cases have related alerts")
                
                # Check 3
                st.markdown("#### 3. Stale Critical Alerts")
                if not results['StaleCriticalAlerts'].empty:
                    st.error(f"⚠️ {len(results['StaleCriticalAlerts'])} critical alerts unresolved >4h")
                    st.dataframe(results['StaleCriticalAlerts'])
                else:
                    st.success("✅ No stale critical alerts")
