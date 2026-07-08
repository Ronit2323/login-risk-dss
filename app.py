"""
app.py
Deployment UI for Intelligent Login Risk Assessment (BI + DSS project).
Run with:
    streamlit run app.py

Flow:
  1. User enters/submits a login event's features (as if this came from
     a live authentication system).
  2. RiskEngine scores it with the trained Isolation Forest pipeline
     (same logic as pipeline.py, applied to one event).
  3. DSS logic maps the risk level to a system action:
        Low       -> Allow Login
        Medium    -> Require MFA
        High      -> Additional Verification
        Critical  -> Block Login & Send Security Alert (emails st125881@ait.asia)
"""

import streamlit as st
import streamlit.components.v1 as components
from risk_engine import RiskEngine
from alert import send_alert

# Changed layout from "centered" to "wide" to beautifully accommodate your full grid dashboard
st.set_page_config(page_title="Login Risk DSS", page_icon="\U0001F510", layout="wide")

st.title("Intelligent Login Risk Assessment")
st.caption("BI + DSS deployment - Isolation Forest anomaly detection with automated decisioning")


@st.cache_resource
def load_engine():
    return RiskEngine()


engine = load_engine()

RISK_COLORS = {
    "Low": "#2e7d32",
    "Medium": "#f9a825",
    "High": "#ef6c00",
    "Critical": "#c62828",
}

# --- Section Tabs ---
# We split the simulator logic and your executive dashboard into professional tabs
tab1, tab2 = st.tabs(["🔒 Interactive Risk Evaluator", "📊 System Risk Analytics & Behavioral Insights"])

with tab1:
    with st.form("login_event_form"):
        st.subheader("Login Event Details")

        col1, col2 = st.columns(2)
        with col1:
            protocol_type = st.selectbox("Protocol type", engine.category_options["protocol_type"])
            encryption_used = st.selectbox("Encryption used", engine.category_options["encryption_used"])
            browser_type = st.selectbox("Browser type", engine.category_options["browser_type"])
            unusual_time_access = st.selectbox("Unusual time access", ["No", "Yes"])

        with col2:
            network_packet_size = st.number_input("Network packet size", min_value=0, value=500)
            login_attempts = st.number_input("Login attempts", min_value=0, value=3)
            failed_logins = st.number_input("Failed logins", min_value=0, value=1)
            session_duration = st.number_input("Session duration (seconds)", min_value=0.0, value=300.0)
            ip_reputation_score = st.slider("IP reputation score (0 = trusted, 1 = malicious)", 0.0, 1.0, 0.3)

        submitted = st.form_submit_button("Evaluate Login")

    if submitted:
        event = {
            "network_packet_size": network_packet_size,
            "protocol_type": protocol_type,
            "login_attempts": login_attempts,
            "session_duration": session_duration,
            "encryption_used": encryption_used,
            "ip_reputation_score": ip_reputation_score,
            "failed_logins": failed_logins,
            "browser_type": browser_type,
            "unusual_time_access": 1 if unusual_time_access == "Yes" else 0,
        }

        try:
            result = engine.score(event)
        except ValueError as e:
            st.error(str(e))
            st.stop()

        color = RISK_COLORS[result["risk_level"]]

        st.markdown("---")
        st.subheader("Result")

        m1, m2 = st.columns(2)
        m1.metric("Risk Score", f"{result['risk_score']} / 100")
        m2.markdown(
            f"<div style='padding:0.6em;border-radius:0.4em;background:{color};"
            f"color:white;text-align:center;font-weight:bold;'>{result['risk_level']} Risk</div>",
            unsafe_allow_html=True,
        )

        st.markdown(f"**Recommended DSS action:** {result['recommended_action']}")

        if result["risk_level"] == "Low":
            st.success("Login allowed. No further action required.")
        elif result["risk_level"] == "Medium":
            st.warning("Multi-Factor Authentication (MFA) requested before granting access.")
        elif result["risk_level"] == "High":
            st.warning("Additional identity verification required (e.g. security questions, callback verification).")
        else:
            st.error("Login blocked. Security team is being notified.")
            alert_result = send_alert(event, result)
            if alert_result["sent"]:
                st.info(alert_result["detail"])
            else:
                st.warning(alert_result["detail"])

        with st.expander("Raw event + model output"):
            st.json({"event": event, "result": result})

with tab2:
    st.subheader("Live SIEM Monitoring Framework")
    
    # Your verified live Tableau Public dashboard link
tableau_url = "https://public.tableau.com/views/BIA_Cyber_Progress_v3_fixed_17834349622720/Overview?:language=en-US&:sid=&:redirect=auth&:display_count=n&:origin=viz_share_link&embed=y&:device=desktop"    
    # We embed the view dynamically using iframe with ample spatial room
components.iframe(tableau_url, width=1300, height=850, scrolling=True)