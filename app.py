import streamlit as st
import streamlit.components.v1 as components
from risk_engine import RiskEngine
from sqlalchemy import create_engine, text
import pandas as pd
import time
import jwt
import uuid
import datetime

# --- 1. DATABASE CONFIGURATION (Cached to fix Red Connection Error) ---
@st.cache_resource
def get_db_engine():
    # We set pool_size to 2 and max_overflow to 0. 
    # This leaves plenty of connections open for Tableau to use!
    return create_engine(
        st.secrets["DB_URI"], 
        pool_size=2, 
        max_overflow=0,
        pool_pre_ping=True,
        pool_recycle=300
    )

db_engine = get_db_engine()

# --- 2. TABLEAU JWT AUTH ---
def generate_tableau_token():
    client_id = st.secrets["TABLEAU_CLIENT_ID"]
    secret_id = st.secrets["TABLEAU_SECRET_ID"]
    secret_value = st.secrets["TABLEAU_SECRET_VALUE"]
    user_email = st.secrets["TABLEAU_USER_EMAIL"]

    now = int(time.time())
    payload = {
        "iss": client_id,
        "exp": now + (10 * 60),
        "iat": now - 60,
        "jti": str(uuid.uuid4()),
        "aud": "tableau",
        "sub": user_email,
        "scp": ["tableau:views:embed", "tableau:views:embed_authoring"]
    }
    return jwt.encode(payload, secret_value, algorithm="HS256", headers={"kid": secret_id, "iss": client_id})

# --- 3. APP SETUP ---
st.set_page_config(page_title="Login Risk DSS", page_icon="🔐", layout="wide")

if "refresh_count" not in st.session_state:
    st.session_state.refresh_count = 0

st.title("Intelligent Login Risk Assessment")
st.caption("Real-time BI + DSS System")

@st.cache_resource
def load_engine():
    return RiskEngine()

engine = load_engine()
RISK_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}

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
        result = engine.score(event)

        # Build sync data
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

        try:
            # Sync to DB
            with db_engine.begin() as connection:
                sync_df.to_sql('login_logs', con=connection, if_exists='append', index=False)
            
            # 🔄 INCREMENT REFRESH COUNTER: This forces the Tableau tab to reload when clicked
            st.session_state.refresh_count += 1
            st.toast("✅ Evaluation synced! Dashboard will refresh.", icon="🚀")
            
        except Exception as e:
            st.error(f"Database error: {e}")

        # Display Results
        color = RISK_COLORS[result["risk_level"]]
        st.markdown("---")
        m1, m2 = st.columns(2)
        m1.metric("Risk Score", f"{result['risk_score']} / 100")
        m2.markdown(f"<div style='padding:0.6em;border-radius:0.4em;background:{color};color:white;text-align:center;font-weight:bold;'>{result['risk_level']} Risk</div>", unsafe_allow_html=True)

with tab2:
    st.subheader("Live SIEM Monitoring Framework")
    try:
        token = generate_tableau_token()
        base_url = "https://10ax.online.tableau.com/t/loginriskproject/views/BIA_Live_Risk_Assessment/Overview"
        
        # We add 'refresh_count' to the URL. 
        # Every time a new evaluation happens, the URL changes slightly, forcing Tableau to reload.
        rid = st.session_state.refresh_count
        embed_url = f"{base_url}?:embed=yes&:token={token}&:refresh=yes&refresh_id={rid}&:showVizHome=no"
        
        components.iframe(embed_url, height=850, scrolling=True)
        
    except Exception as e:
        st.error(f"Authentication Error: {e}")