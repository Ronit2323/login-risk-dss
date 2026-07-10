import streamlit as st
import streamlit.components.v1 as components
from risk_engine import RiskEngine
from sqlalchemy import create_engine, text
import pandas as pd
import time
import jwt
import uuid
import datetime

# --- 1. DATABASE CONFIGURATION ---
@st.cache_resource
def get_db_engine():
    return create_engine(
        st.secrets["DB_URI"],
        pool_size=1,
        max_overflow=0,
        pool_pre_ping=True,
        pool_recycle=600 
    )

db_engine = get_db_engine()

# --- 2. TABLEAU JWT AUTH ---
def generate_tableau_token():
    payload = {
        "iss": st.secrets["TABLEAU_CLIENT_ID"],
        "exp": int(time.time()) + (10 * 60),
        "iat": int(time.time()) - 60,
        "jti": str(uuid.uuid4()),
        "aud": "tableau",
        "sub": st.secrets["TABLEAU_USER_EMAIL"],
        "scp": ["tableau:views:embed", "tableau:views:embed_authoring"]
    }
    return jwt.encode(payload, st.secrets["TABLEAU_SECRET_VALUE"], algorithm="HS256", 
                      headers={"kid": st.secrets["TABLEAU_SECRET_ID"], "iss": st.secrets["TABLEAU_CLIENT_ID"]})

# --- 3. APP SETUP & SCROLL-READY CSS ---
st.set_page_config(page_title="Login Risk DSS", page_icon="🔐", layout="wide")

st.markdown("""
    <style>
    /* 1. Use the full browser width */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 5rem !important;
        max-width: 98% !important;
    }
    
    /* 2. ALLOW normal browser scrolling for the whole page */
    .main {
        overflow: auto !important;
    }

    /* 3. Style the sidebar to look clean */
    [data-testid="stSidebar"] {
        background-color: #f8fafc;
        border-right: 1px solid #e2e8f0;
    }
    </style>
    """, unsafe_allow_html=True)

# --- SIDEBAR ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=60)
st.sidebar.title("Project HeHeHe")
st.sidebar.info("**Topic:** Intelligent Login Risk Assessment")
with st.sidebar.expander("Team Members", expanded=True):
    st.write("• Somkamon Mettawiharee")
    st.write("• Meta Puspa Maulida")
    st.write("• Ronit Gurung")

if "refresh_count" not in st.session_state:
    st.session_state.refresh_count = 0

st.title("🛡️ Intelligent Login Risk Command Center")

engine = RiskEngine()
RISK_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}

tab1, tab2 = st.tabs(["🔒 Manual Risk Evaluator", "📊 Live System Analytics"])

with tab1:
    col_l, col_r = st.columns([2, 1])
    with col_l:
        with st.form("login_event_form"):
            st.subheader("Session Context")
            c1, c2 = st.columns(2)
            with c1:
                protocol_type = st.selectbox("Protocol", engine.category_options["protocol_type"])
                encryption_used = st.selectbox("Encryption", engine.category_options["encryption_used"])
                browser_type = st.selectbox("Browser", engine.category_options["browser_type"])
                unusual_time = st.selectbox("Unusual Time Access", ["No", "Yes"])
            with c2:
                network_packet = st.number_input("Packet Size", min_value=0, value=500)
                attempts = st.number_input("Total Attempts", min_value=1, value=3)
                failed = st.number_input("Failed Logins", min_value=0, value=1)
                duration = st.number_input("Duration (sec)", min_value=0.0, value=300.0)
                ip_rep = st.slider("IP Reputation", 0.0, 1.0, 0.3)
            submitted = st.form_submit_button("ANALYZE SESSION")

    if submitted:
        unusual_time_val = 1 if unusual_time == "Yes" else 0
        event = {"network_packet_size": network_packet, "protocol_type": protocol_type,
                 "login_attempts": attempts, "session_duration": duration,
                 "encryption_used": encryption_used, "ip_reputation_score": ip_rep,
                 "failed_logins": failed, "browser_type": browser_type,
                 "unusual_time_access": unusual_time_val}
        result = engine.score(event)

        sync_df = pd.DataFrame([{
            "session_id": f"LIVE_{int(time.time())}", "network_packet_size": network_packet,
            "protocol_type": protocol_type, "login_attempts": attempts,
            "session_duration": duration, "encryption_used": encryption_used,
            "ip_reputation_score": ip_rep, "failed_logins": failed,
            "browser_type": browser_type, "unusual_time_access": unusual_time_val,
            "risk_score": result["risk_score"], "risk_level": result["risk_level"],
            "recommended_action": result["recommended_action"],
            "attack_detected": 1 if result["risk_score"] >= 55 else 0,
            "anomaly_score": round(result["risk_score"] / 100, 4),
            "iso_flag": 1 if result["risk_score"] >= 55 else 0,
            "attack_label": "Attack Detected" if result["risk_score"] >= 55 else "Normal",
            "unusual_time_label": "Unusual Hours" if unusual_time == "Yes" else "Normal Hours",
            "risk_rank": {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(result["risk_level"], 1),
            "failed_login_ratio": round(failed / attempts, 2) if attempts > 0 else 0,
            "session_duration_min": round(duration / 60, 2)
        }])

        try:
            with db_engine.begin() as conn:
                sync_df.to_sql('login_logs', con=conn, if_exists='append', index=False)
            st.session_state.refresh_count += 1
            st.toast("🚀 Database Updated!", icon="✅")
        except Exception as e:
            st.error(f"DB Error: {e}")

        with col_r:
            st.subheader("Decision Output")
            color = RISK_COLORS[result["risk_level"]]
            st.metric("Risk Index", f"{result['risk_score']}%")
            st.markdown(f"<div style='padding:15px; border-radius:10px; background:{color}; color:white; text-align:center; font-weight:bold;'>{result['risk_level'].upper()} RISK</div>", unsafe_allow_html=True)
            st.markdown(f"**Action:** `{result['recommended_action']}`")

    # --- HISTORY SECTION ---
    st.markdown("---")
    st.subheader("📊 Recent System Activity")
    try:
        query = "SELECT created_at, session_id, protocol_type, risk_level, risk_score FROM login_logs ORDER BY created_at DESC LIMIT 10"
        recent_data = pd.read_sql(query, db_engine)
        st.dataframe(recent_data, use_container_width=True)
    except:
        st.info("Awaiting telemetry...")

with tab2:
    try:
        token = generate_tableau_token()
        base_url = "https://10ax.online.tableau.com/t/loginriskproject/views/BIA_Live_Risk_Assessment/Overview"
        rid = st.session_state.refresh_count
        
        # Build the final URL (1300px wide, 800px high)
        # :toolbar=yes allows you to use the refresh/undo buttons in Tableau
        embed_url = f"{base_url}?:embed=yes&:tabs=no&:toolbar=yes&:showVizHome=no&:token={token}&:refresh=yes&refresh_id={rid}"
        
        # We set the iframe to your EXACT dashboard size
        # This will create a horizontal scrollbar if the user's screen is too small, 
        # but the dashboard itself will be 100% visible and un-clipped.
        st.components.v1.iframe(embed_url, width=1300, height=850, scrolling=True)
        
    except Exception as e:
        st.error(f"Tableau Connection Error: {e}")