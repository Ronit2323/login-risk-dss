import streamlit as st
import streamlit.components.v1 as components
from risk_engine import RiskEngine
from sqlalchemy import create_engine
import pandas as pd
import time
import jwt
import uuid

# --- 1. Database Configuration ---
DB_URI = st.secrets["DB_URI"]
db_engine = create_engine(DB_URI, pool_pre_ping=True)

# --- 2. Tableau JWT Token Generation ---
def generate_tableau_token():
    payload = {
        "iss": st.secrets["TABLEAU_CLIENT_ID"],
        "sub": st.secrets["TABLEAU_USER_EMAIL"],
        "aud": "tableau",
        "exp": int(time.time()) + (10 * 60),
        "jti": str(uuid.uuid4()),
        "scp": ["tableau:views:embed"]
    }
    headers = {
        "kid": st.secrets["TABLEAU_SECRET_ID"],
        "iss": st.secrets["TABLEAU_CLIENT_ID"]
    }
    return jwt.encode(payload, st.secrets["TABLEAU_SECRET_VALUE"], algorithm="HS256", headers=headers)

# --- 3. App Setup ---
st.set_page_config(page_title="Login Risk DSS", page_icon="🔐", layout="wide")
st.title("Intelligent Login Risk Assessment")

@st.cache_resource
def load_engine():
    return RiskEngine()

engine = load_engine()
RISK_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}

if "last_evaluated_protocol" not in st.session_state:
    st.session_state.last_evaluated_protocol = None

# --- 4. Tabs ---
tab1, tab2 = st.tabs(["🔒 Interactive Risk Evaluator", "📊 System Risk Analytics & Behavioral Insights"])

with tab1:
    with st.form("login_event_form"):
        st.subheader("Login Event Details")
        col1, col2 = st.columns(2)
        with col1:
            protocol_type = st.selectbox("Protocol type", engine.category_options["protocol_type"])
            encryption_used = st.selectbox("Encryption used", engine.category_options["encryption_used"])
            browser_type = st.selectbox("Browser type", engine.category_options["browser_type"])
            unusual_time_access_str = st.selectbox("Unusual time access", ["No", "Yes"])
        with col2:
            network_packet_size = st.number_input("Network packet size", min_value=0, value=500)
            login_attempts = st.number_input("Login attempts", min_value=1, value=3)
            failed_logins = st.number_input("Failed logins", min_value=0, value=1)
            session_duration = st.number_input("Session duration (seconds)", min_value=0.0, value=300.0)
            ip_reputation_score = st.slider("IP reputation score", 0.0, 1.0, 0.3)
        submitted = st.form_submit_button("Evaluate Login")

    if submitted:
        unusual_time_val = 1 if unusual_time_access_str == "Yes" else 0
        event = {
            "network_packet_size": network_packet_size, "protocol_type": protocol_type,
            "login_attempts": login_attempts, "session_duration": session_duration,
            "encryption_used": encryption_used, "ip_reputation_score": ip_reputation_score,
            "failed_logins": failed_logins, "browser_type": browser_type,
            "unusual_time_access": unusual_time_val,
        }
        st.session_state.last_evaluated_protocol = protocol_type
        result = engine.score(event)

        sync_df = pd.DataFrame([{
            "session_id": f"LIVE_{int(time.time())}",
            "network_packet_size": network_packet_size,
            "protocol_type": protocol_type,
            "login_attempts": login_attempts,
            "session_duration": session_duration,
            "encryption_used": encryption_used,
            "ip_reputation_score": ip_reputation_score,
            "failed_logins": failed_logins,
            "browser_type": browser_type,
            "unusual_time_access": unusual_time_val,
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "recommended_action": result["recommended_action"],
            "attack_detected": 1 if result["risk_score"] >= 55 else 0,
            "anomaly_score": round(result["risk_score"] / 100, 4),
            "iso_flag": 1 if result["risk_score"] >= 55 else 0,
            "attack_label": "Attack Detected" if result["risk_score"] >= 55 else "Normal",
            "unusual_time_label": "Unusual Hours" if unusual_time_val == 1 else "Normal Hours",
            "risk_rank": {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(result["risk_level"], 1),
            "failed_login_ratio": round(failed_logins / login_attempts, 2) if login_attempts > 0 else 0,
            "session_duration_min": round(session_duration / 60, 2)
        }])
        sync_df.to_sql('login_logs', db_engine, if_exists='append', index=False)
        st.toast("✅ Evaluation synced to Cloud Database!", icon="☁️")

        color = RISK_COLORS[result["risk_level"]]
        st.markdown("---")
        m1, m2 = st.columns(2)
        m1.metric("Risk Score", f"{result['risk_score']} / 100")
        m2.markdown(f"<div style='padding:0.6em;border-radius:0.4em;background:{color};color:white;text-align:center;font-weight:bold;'>{result['risk_level']} Risk</div>", unsafe_allow_html=True)

with tab2:
    st.subheader("Live SIEM Monitoring Framework")
    try:
        token = generate_tableau_token()
        # Corrected URL: Ensure it is the View URL, NOT the Authoring URL
        base_url = "https://10ax.online.tableau.com/t/loginriskproject/views/BIA_Live_Risk_Assessment/Overview"
        embed_url = f"{base_url}?:embed=y&:token={token}&:refresh=y&:showVizHome=n&:toolbar=n"
        
        # Inject the iframe as raw HTML to support the 'allow' attribute
        tableau_html = f"""
        <iframe 
            src="{embed_url}" 
            width="100%" 
            height="900" 
            frameborder="0" 
            allow="fullscreen; clipboard-read; clipboard-write; display-capture; geolocation; microphone; camera; midi; encrypted-media">
        </iframe>
        """
        st.markdown(tableau_html, unsafe_allow_html=True)
        
    except Exception as e:
        st.error(f"Authentication Error: {e}")