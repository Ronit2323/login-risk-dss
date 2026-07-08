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
st.set_page_config(page_title="Login Risk DSS", page_icon="🔐", layout="wide")

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
    
    # FIX: These lines are now properly indented to lock inside Tab 2
    tableau_js_code = """
    <div class='tableauPlaceholder' id='viz1783484224593' style='position: relative; margin: 0 auto;'>
        <noscript>
            <a href='#'><img alt='Overview ' src='https://public.tableau.com/static/images/BI/BIA_Cyber_Progress_v3_fixed_17834349622720/Overview/1_rss.png' style='border: none' /></a>
        </noscript>
        <object class='tableauViz' style='display:none;'>
            <param name='host_url' value='https%3A%2F%2Fpublic.tableau.com%2F' /> 
            <param name='embed_code_version' value='3' /> 
            <param name='site_root' value='' />
            <param name='name' value='BIA_Cyber_Progress_v3_fixed_17834349622720/Overview' />
            <param name='tabs' value='no' />
            <param name='toolbar' value='yes' />
            <param name='static_image' value='https://public.tableau.com/static/images/BI/BIA_Cyber_Progress_v3_fixed_17834349622720/Overview/1.png' /> 
            <param name='animate_transition' value='yes' />
            <param name='display_static_image' value='yes' />
            <param name='display_spinner' value='yes' />
            <param name='display_overlay' value='yes' />
            <param name='display_count' value='yes' />
            <param name='language' value='en-US' />
            <param name='device' value='desktop' />
        </object>
    </div>
    <script type='text/javascript'>
        var divElement = document.getElementById('viz1783484224593');
        var vizElement = divElement.getElementsByTagName('object')[0];
        vizElement.style.width='1300px';
        vizElement.style.height='850px';
        var scriptElement = document.createElement('script');
        scriptElement.src = 'https://public.tableau.com/javascripts/api/viz_v1.js';
        vizElement.parentNode.insertBefore(scriptElement, vizElement);
    </script>
    """

    # FIX: Render component safely inside Tab 2's context execution sequence
    components.html(tableau_js_code, width=1340, height=870, scrolling=False)