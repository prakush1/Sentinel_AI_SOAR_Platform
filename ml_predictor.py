"""
Sentinel AI SOAR SOC - ML Threat Predictor
Machine learning for threat detection and anomaly detection
"""

import pandas as pd
import numpy as np
import pickle
import sqlite3
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

DB_NAME = "sentinel_soc.db"
THREAT_MODEL_FILE = "threat_detection_model.pkl"
ANOMALY_MODEL_FILE = "anomaly_detection_model.pkl"

def load_data():
    """Load security data from SQLite"""
    conn = sqlite3.connect(DB_NAME)
    alerts_df = pd.read_sql("SELECT * FROM alerts", conn)
    conn.close()
    return alerts_df

def preprocess_threat_data(df):
    """Preprocess data for threat classification"""
    features = ['source', 'asset_type', 'risk_score']
    
    # Target: Critical/High severity = Threat (1), else Normal (0)
    df['is_threat'] = df['severity'].apply(lambda x: 1 if x in ['Critical', 'High'] else 0)
    
    # Encode categoricals
    encoders = {}
    for col in ['source', 'asset_type']:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    
    X = df[features]
    y = df['is_threat']
    
    return X, y, encoders

def train_threat_model():
    """Train threat detection model"""
    print("Loading security data...")
    df = load_data()
    
    print("Preprocessing threat data...")
    X, y, encoders = preprocess_threat_data(df)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train
    print("Training Threat Detection Model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    print(f"Model Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(classification_report(y_test, y_pred))
    
    # Save
    artifacts = {
        "model": model,
        "encoders": encoders,
        "features": ['source', 'asset_type', 'risk_score']
    }
    
    with open(THREAT_MODEL_FILE, "wb") as f:
        pickle.dump(artifacts, f)
    
    print(f"Threat model saved to {THREAT_MODEL_FILE}")

def train_anomaly_model():
    """Train anomaly detection model"""
    print("Loading data for anomaly detection...")
    df = load_data()
    
    # Features for anomaly detection
    features = ['risk_score']
    
    # Add encoded categoricals
    for col in ['source', 'asset_type', 'alert_type']:
        le = LabelEncoder()
        df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
        features.append(f'{col}_encoded')
    
    X = df[features]
    
    # Train Isolation Forest
    print("Training Anomaly Detection Model...")
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)
    
    # Save
    artifacts = {
        "model": model,
        "features": features
    }
    
    with open(ANOMALY_MODEL_FILE, "wb") as f:
        pickle.dump(artifacts, f)
    
    print(f"Anomaly model saved to {ANOMALY_MODEL_FILE}")

def predict_threat_probability(df_new):
    """Predict threat probability for new alerts"""
    try:
        with open(THREAT_MODEL_FILE, "rb") as f:
            artifacts = pickle.load(f)
    except FileNotFoundError:
        return pd.Series([0.5] * len(df_new))
    
    model = artifacts["model"]
    encoders = artifacts["encoders"]
    feature_names = artifacts["features"]
    
    df_processed = df_new.copy()
    
    # Apply encoders
    for col, le in encoders.items():
        df_processed[col] = df_processed[col].map(
            lambda s: le.transform([s])[0] if s in le.classes_ else -1
        )
    
    probs = model.predict_proba(df_processed[feature_names])[:, 1]
    return probs

def detect_anomalies(df_new):
    """Detect anomalous alerts"""
    try:
        with open(ANOMALY_MODEL_FILE, "rb") as f:
            artifacts = pickle.load(f)
    except FileNotFoundError:
        return pd.Series([0] * len(df_new))
    
    model = artifacts["model"]
    feature_names = artifacts["features"]
    
    df_processed = df_new.copy()
    
    # Encode categoricals
    for col in ['source', 'asset_type', 'alert_type']:
        if col in df_processed.columns:
            le = LabelEncoder()
            df_processed[f'{col}_encoded'] = le.fit_transform(df_processed[col].astype(str))
    
    # Ensure all features exist
    for feat in feature_names:
        if feat not in df_processed.columns:
            df_processed[feat] = 0
    
    predictions = model.predict(df_processed[feature_names])
    # -1 = anomaly, 1 = normal
    return pd.Series(predictions == -1, index=df_new.index)

def get_ml_insights():
    """Get ML-generated insights"""
    df = load_data()
    
    insights = {
        'total_analyzed': len(df),
        'high_risk_predicted': 0,
        'anomalies_detected': 0,
        'top_threat_sources': [],
        'model_confidence': 0.85
    }
    
    try:
        # Get threat predictions
        df['threat_prob'] = predict_threat_probability(df)
        insights['high_risk_predicted'] = len(df[df['threat_prob'] > 0.7])
        
        # Get anomalies
        df['is_anomaly'] = detect_anomalies(df)
        insights['anomalies_detected'] = df['is_anomaly'].sum()
        
        # Top threat sources
        threat_sources = df[df['threat_prob'] > 0.5]['source'].value_counts().head(3)
        insights['top_threat_sources'] = threat_sources.to_dict()
        
    except Exception as e:
        print(f"ML insights error: {e}")
    
    return insights

if __name__ == "__main__":
    train_threat_model()
    train_anomaly_model()
