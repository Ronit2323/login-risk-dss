"""
alert.py
Sends a security alert email when the DSS decides a login event is Critical
risk (Block Login & Send Security Alert).

SMTP credentials are read from environment variables so no secrets are
ever hard-coded in this file or committed to a report/repo:

    SMTP_HOST       e.g. smtp.gmail.com  (Gmail example, any SMTP works)
    SMTP_PORT       e.g. 587
    SMTP_USER       the sending mailbox address
    SMTP_PASSWORD   the mailbox password / app password

Set them before running the app, e.g. on Linux/Mac:
    export SMTP_HOST=smtp.gmail.com
    export SMTP_PORT=587
    export SMTP_USER=youraddress@gmail.com
    export SMTP_PASSWORD=your_app_password

On Windows (PowerShell):
    $env:SMTP_HOST="smtp.gmail.com"
    $env:SMTP_PORT="587"
    $env:SMTP_USER="youraddress@gmail.com"
    $env:SMTP_PASSWORD="your_app_password"

If credentials are not set, send_alert() will NOT crash the app - it will
return a status dict saying the email was skipped, so the demo still runs
end-to-end without real SMTP access.
"""

import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone

ALERT_RECIPIENT = "st125881@ait.asia"


def _get_credential(key: str):
    """
    Look for SMTP credentials in this order:
      1. Streamlit secrets (st.secrets) - used on Streamlit Community Cloud
      2. Environment variables - used for local runs
    Returns None if not found anywhere (caller handles the missing case).
    """
    try:
        import streamlit as st
        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass  # not running inside Streamlit, or no secrets.toml configured
    return os.environ.get(key)


def send_alert(event: dict, result: dict) -> dict:
    """
    event  : the raw login event dict that was scored
    result : the dict returned by RiskEngine.score()  (risk_score, risk_level, ...)

    Returns {"sent": bool, "detail": str}
    """
    host = _get_credential("SMTP_HOST")
    port = _get_credential("SMTP_PORT")
    user = _get_credential("SMTP_USER")
    password = _get_credential("SMTP_PASSWORD")

    if not all([host, port, user, password]):
        return {
            "sent": False,
            "detail": (
                "SMTP credentials not configured (SMTP_HOST/PORT/USER/PASSWORD "
                "environment variables). Alert was generated but not emailed."
            ),
        }

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    body_lines = [
        "SECURITY ALERT - Critical Risk Login Detected",
        "",
        f"Timestamp:            {timestamp}",
        f"Risk Score:           {result['risk_score']} / 100",
        f"Risk Level:           {result['risk_level']}",
        f"Recommended Action:   {result['recommended_action']}",
        "",
        "Login event details:",
        f"  Protocol type:        {event.get('protocol_type')}",
        f"  Encryption used:      {event.get('encryption_used')}",
        f"  Browser type:         {event.get('browser_type')}",
        f"  Login attempts:       {event.get('login_attempts')}",
        f"  Failed logins:        {event.get('failed_logins')}",
        f"  Session duration (s): {event.get('session_duration')}",
        f"  IP reputation score:  {event.get('ip_reputation_score')}",
        f"  Unusual time access:  {event.get('unusual_time_access')}",
        f"  Network packet size:  {event.get('network_packet_size')}",
        "",
        "This login has been automatically blocked pending review.",
    ]
    body = "\n".join(body_lines)

    msg = MIMEText(body)
    msg["Subject"] = f"[CRITICAL] Login Risk Alert - Score {result['risk_score']}"
    msg["From"] = user
    msg["To"] = ALERT_RECIPIENT

    try:
        with smtplib.SMTP(host, int(port), timeout=10) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, [ALERT_RECIPIENT], msg.as_string())
        return {"sent": True, "detail": f"Alert emailed to {ALERT_RECIPIENT}."}
    except Exception as e:
        return {"sent": False, "detail": f"Email send failed: {e}"}
