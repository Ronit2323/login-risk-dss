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

# --- 3. APP SETUP & CSS ---
st.set_page_config(page_title="Login Risk DSS", page_icon="🔐", layout="wide")

st.markdown("""
    <style>
    /* 1. Reduce padding to use full screen height */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 0rem !important;
        max-width: 100% !important;
    }
    
    /* 2. Narrower Sidebar */
    [data-testid="stSidebar"] {
        width: 250px !important;
    }
    
    /* 3. Scaling Container for the Dashboard */
    /* This forces the 1300x800 dashboard to fit into the width of the tab */
    .tableau-scaling-wrapper {
        width: 100%;
        overflow: hidden;
    }
    
    .tableau-container {
        width: 1300px;
        height: 800px;
        transform-origin: top left;
    }

    /* Auto-scale down based on screen width */
    @media (max-width: 1400px) {
        .tableau-container { transform: scale(0.85); }
    }
    @media (max-width: 1200px) {
        .tableau-container { transform: scale(0.75); }
    }
    @media (max-width: 1000px) {
        .tableau-container { transform: scale(0.65); }
    }
    </style>
    """, unsafe_allow_html=True)

# --- SIDEBAR: TEAM INFO ---
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=80)
st.sidebar.title("Project HeHeHe")
st.sidebar.info("**Topic:** Intelligent Login Risk Assessment")

with st.sidebar.expander("Team Members"):
    st.write("1. Somkamon Mettawiharee")
    st.write("2. Meta Puspa Maulida")
    st.write("3. Ronit Gurung")

if "refresh_count" not in st.session_state:
    st.session_state.refresh_count = 0

st.title("🛡️ Intelligent Login Risk Command Center")
st.caption("A Decision Support System for Behavior-Based Risk Analytics")

engine = RiskEngine()
RISK_COLORS = {"Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00", "Critical": "#c62828"}

tab1, tab2 = st.tabs(["🔒 Manual Risk Evaluator", "📊 Live System Analytics"])

with tab1:
    col_l, col_r = st.columns([2, 1])
    
    with col_l:
        with st.form("login_event_form"):
            st.subheader("Login Session Context")
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
            st.metric("Risk Index", f"{result['risk_score']} / 100")
            st.markdown(f"<div style='padding:15px; border-radius:10px; background:{color}; color:white; text-align:center; font-weight:bold;'>{result['risk_level'].upper()} RISK</div>", unsafe_allow_html=True)
            st.markdown(f"**Action:** `{result['recommended_action']}`")
            
            if result["risk_level"] == "Low": st.success("LOGIN ALLOWED")
            elif result["risk_level"] == "Critical": st.error("BLOCK & ALERT ADMIN")
            else: st.warning("VERIFICATION REQUIRED")

    st.markdown("---")
    st.subheader("📊 Recent Command Center Activity")
    try:
        query = "SELECT session_id, created_at, protocol_type, risk_level, risk_score FROM login_logs ORDER BY created_at DESC LIMIT 5"
        recent_data = pd.read_sql(query, db_engine)
        st.dataframe(recent_data, use_container_width=True)
    except:
        st.info("Loading activity feed...")

with tab2:
    try:
        token = generate_tableau_token()
        base_url = "https://10ax.online.tableau.com/t/loginriskproject/views/BIA_Live_Risk_Assessment/Overview"
        rid = st.session_state.refresh_count
        
        embed_url = f"{base_url}?:embed=true&:toolbar=no&:showVizHome=no&:token={token}&:refresh=yes&refresh_id={rid}"
        
        # We wrap the iframe in a scaling div to prevent scrolling
        tableau_html = f"""
        <style>
            .tableau-container {{
                width: 1300px;
                height: 800px;
                transform-origin: top left;
                transform: scale(min(1, (window.innerWidth / 1350)));
            }}
        </style>
        <div class="tableau-scaling-wrapper">
            <div class="tableau-container">
                <iframe 
                    src="{embed_url}" 
                    width="1300" 
                    height="800" 
                    style="border:none; overflow:hidden;"
                    scrolling="no">
                </iframe>
            </div>
        </div>
        """
        # Height 850 catches the scaled dashboard and ensures the refresh bar at bottom is visible
        components.html(tableau_html, height=850, scrolling=False)
        
    except Exception as e:
        st.error(f"Tableau Connection Error: {e}")