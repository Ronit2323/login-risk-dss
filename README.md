# Intelligent Login Risk Assessment - Deployment

A live BI + DSS deployment of the group's Isolation Forest login-risk pipeline.
A user (or auth system) submits one login event; the app scores it with the
same model logic as `pipeline.py`, then applies the Decision Support System
rules below.

| Risk Level | Risk Score | Action                                  |
|------------|------------|------------------------------------------|
| Low        | 0 - 29     | Allow Login                               |
| Medium     | 30 - 54    | Require MFA                               |
| High       | 55 - 74    | Additional Verification                   |
| Critical   | 75 - 100   | Block Login & Send Security Alert (email) |

Critical-risk events trigger an automated email alert to **st125881@ait.asia**.

## Folder contents

```
deployment/
  train_model.py          # one-time training script (already run for you)
  artifacts/               # saved model, scaler, and metadata
    model.joblib
    scaler.joblib
    feature_columns.json
    category_options.json
    score_bounds.json
  risk_engine.py           # scores a single login event -> risk_score/level/action
  alert.py                 # sends the Critical-risk email alert via SMTP
  app.py                   # Streamlit UI that ties it all together
  requirements.txt
```

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. (Optional but needed for real emails) Set your SMTP credentials as
   environment variables so `alert.py` can send the Critical-risk alert.
   Example using a Gmail account with an App Password:
   ```
   export SMTP_HOST=smtp.gmail.com
   export SMTP_PORT=587
   export SMTP_USER=your_address@gmail.com
   export SMTP_PASSWORD=your_16_char_app_password
   ```
   If you skip this step, the app still runs end-to-end - it will just show
   "Alert was generated but not emailed" instead of crashing, which is
   useful for a live classroom demo where you may not want to configure
   real SMTP access.

3. Run the app:
   ```
   streamlit run app.py
   ```
   This opens a local web page where you can enter a login event's
   features (protocol, encryption, browser, login attempts, failed
   logins, session duration, IP reputation score, unusual time access)
   and see the risk score, risk level, and DSS action in real time.

## Deploying on Streamlit Community Cloud

1. **Create a GitHub repository**
   - Go to github.com, sign in (or create a free account).
   - Click **New repository**, give it a name (e.g. `login-risk-dss`), set it
     to **Public** (required for the free tier), and click **Create repository**.

2. **Upload this folder's contents**
   - On your new repo page, click **Add file -> Upload files**.
   - Drag in everything from the `deployment` folder: `app.py`, `risk_engine.py`,
     `alert.py`, `train_model.py`, `requirements.txt`, `README.md`, `.gitignore`,
     and the whole `artifacts/` folder (model.joblib, scaler.joblib, and the
     3 .json files). Do **not** upload `secrets.toml.example` if you've already
     filled in real credentials in it - upload the blank example only, or skip it.
   - Commit the files (green **Commit changes** button).

3. **Sign up for Streamlit Community Cloud**
   - Go to share.streamlit.io.
   - Click **Sign in / Sign up** and choose **Continue with GitHub**, then
     authorize Streamlit to access your repositories.

4. **Create the app**
   - Click **Create app** (or **New app**).
   - Choose **Deploy a public app from GitHub**.
   - Pick your repository (`login-risk-dss`), branch (`main`), and set
     **Main file path** to `app.py` (if `app.py` sits inside a `deployment/`
     subfolder in the repo, the path would be `deployment/app.py`).
   - Click **Deploy**.

5. **Add your email secrets**
   - Once the app is created (it may show an error until secrets are set - that's fine),
     go to its page, click the **⋮** menu (top right) -> **Settings** -> **Secrets**.
   - Paste in:
     ```
     SMTP_HOST = "smtp.gmail.com"
     SMTP_PORT = "587"
     SMTP_USER = "youraddress@gmail.com"
     SMTP_PASSWORD = "your_16_char_app_password"
     ```
   - Click **Save**. The app will automatically reboot and pick these up via
     `st.secrets` (already wired up in `alert.py`).
   - If you use Gmail, you need an **App Password**, not your normal Gmail
     password: Google Account -> Security -> 2-Step Verification (turn on) ->
     App passwords -> generate one for "Mail".

6. **Test it**
   - Open the app's public URL (shown at the top of the Streamlit Cloud page,
     looks like `https://your-app-name.streamlit.app`).
   - Fill in a login event that should score Critical (e.g. high failed
     logins, high IP reputation score, unusual time access = Yes) and submit.
   - You should see "Login blocked" plus a message confirming the alert was
     emailed to st125881@ait.asia. Check that inbox to confirm delivery.

7. **Share the link**
   - The `https://your-app-name.streamlit.app` URL is public and shareable -
     this is what you can put in your presentation or send to your instructor
     and teammates (Meta, Ronit) to try live.

## Retraining

If the underlying dataset changes, re-run:
```
python train_model.py
```
This regenerates everything in `artifacts/` using the same cleaning and
Isolation Forest settings as `pipeline.py` (200 estimators, 15% contamination,
random_state=42), so the deployed model always matches the batch pipeline
used for the group's BI dashboard.

## Why a single-event engine differs slightly from the batch pipeline

`pipeline.py` fits the scaler and Isolation Forest on the WHOLE historical
dataset, then normalizes anomaly scores using that batch's own min/max.
A production system scores ONE new login at a time, so `risk_engine.py`
reuses the exact scaler, model, and min/max bounds learned during training
(saved in `artifacts/`) and applies them to the new single event. This keeps
the live risk score directly comparable to the historical risk scores in the
dashboard, instead of re-normalizing against a batch of one.
