import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

import streamlit as st
import streamlit.components.v1 as components

from backend import (
    check_email,
    check_password,
    check_vpn_ip,
    check_domain,
    check_phone,
    store_scan,
    wipe_database
)


# ── Page config ─────────────────────────
st.set_page_config(page_title="ONION_RINGS", layout="wide")


# ── Database Setup ──────────────────────
DB_FILE = "onion_rings.db"


def get_stored_values(column):

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    allowed_columns = ["email", "password_hash", "vpn_ip", "api_domain", "phone"]

    if column not in allowed_columns:
        return []

    rows = c.execute(
        f"SELECT DISTINCT {column} FROM scans WHERE {column} IS NOT NULL"
    ).fetchall()

    conn.close()

    return [r[0] for r in rows]


# ── Country Code Mapping ─────────────────
COUNTRY_CODES = {
    "🇮🇳 India (+91)":           {"code": "IN", "dial": "+91"},
    "🇺🇸 United States (+1)":    {"code": "US", "dial": "+1"},
    "🇬🇧 United Kingdom (+44)":  {"code": "GB", "dial": "+44"},
    "🇦🇺 Australia (+61)":       {"code": "AU", "dial": "+61"},
    "🇨🇦 Canada (+1)":           {"code": "CA", "dial": "+1"},
    "🇩🇪 Germany (+49)":         {"code": "DE", "dial": "+49"},
    "🇫🇷 France (+33)":          {"code": "FR", "dial": "+33"},
    "🇯🇵 Japan (+81)":           {"code": "JP", "dial": "+81"},
    "🇨🇳 China (+86)":           {"code": "CN", "dial": "+86"},
    "🇧🇷 Brazil (+55)":          {"code": "BR", "dial": "+55"},
    "🇷🇺 Russia (+7)":           {"code": "RU", "dial": "+7"},
    "🇿🇦 South Africa (+27)":    {"code": "ZA", "dial": "+27"},
    "🇳🇬 Nigeria (+234)":        {"code": "NG", "dial": "+234"},
    "🇲🇽 Mexico (+52)":          {"code": "MX", "dial": "+52"},
    "🇸🇬 Singapore (+65)":       {"code": "SG", "dial": "+65"},
    "🇦🇪 UAE (+971)":            {"code": "AE", "dial": "+971"},
    "🇸🇦 Saudi Arabia (+966)":   {"code": "SA", "dial": "+966"},
    "🇮🇩 Indonesia (+62)":       {"code": "ID", "dial": "+62"},
    "🇵🇰 Pakistan (+92)":        {"code": "PK", "dial": "+92"},
    "🇧🇩 Bangladesh (+880)":     {"code": "BD", "dial": "+880"},
    "🇵🇭 Philippines (+63)":     {"code": "PH", "dial": "+63"},
    "🇰🇷 South Korea (+82)":     {"code": "KR", "dial": "+82"},
    "🇮🇹 Italy (+39)":           {"code": "IT", "dial": "+39"},
    "🇪🇸 Spain (+34)":           {"code": "ES", "dial": "+34"},
    "🇳🇱 Netherlands (+31)":     {"code": "NL", "dial": "+31"},
}


# ── Hacker Rain Background ──────────────
components.html(
"""
<style>
body{
margin:0;
overflow:hidden;
background:black;
}

canvas{
position:fixed;
top:0;
left:0;
width:100vw;
height:100vh;
}
</style>

<canvas id="matrix"></canvas>

<script>

const canvas = document.getElementById("matrix");
const ctx = canvas.getContext("2d");

function resize(){
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
}

resize();
window.addEventListener("resize", resize);

const letters = "01ONIONRINGS";
const fontSize = 18;
const columns = Math.floor(canvas.width/fontSize);

const drops = [];

for(let i=0;i<columns;i++){
drops[i] = 1;
}

function draw(){

ctx.fillStyle = "rgba(0,0,0,0.08)";
ctx.fillRect(0,0,canvas.width,canvas.height);

ctx.fillStyle = "#00ff41";
ctx.font = fontSize + "px monospace";

for(let i=0;i<drops.length;i++){

const text = letters[Math.floor(Math.random()*letters.length)];

ctx.fillText(text,i*fontSize,drops[i]*fontSize);

if(drops[i]*fontSize > canvas.height && Math.random() > 0.975){
drops[i] = 0;
}

drops[i]++;

}

}

setInterval(draw,33);

</script>
""",
height=1
)


# ── Force background behind UI ──────────
st.markdown("""
<style>

iframe{
position:fixed !important;
top:0;
left:0;
width:100vw;
height:100vh;
z-index:-1;
border:none;
}

.stApp{
background:transparent !important;
}

</style>
""", unsafe_allow_html=True)


# ── UI Styling ─────────────────────────
st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, .stApp{
font-family:'JetBrains Mono', monospace !important;
font-size:22px !important;
color:#a8ffcf;
}

h1{
font-family:'Orbitron', sans-serif !important;
font-size:2.5rem !important;
color:#00ff41;
text-shadow:0 0 10px #00ff41;
}

h2{
font-family:'Orbitron', sans-serif !important;
font-size:2.2rem !important;
color:#00ff41;
}

h3{
font-family:'Orbitron', sans-serif !important;
font-size:1.5rem !important;
color:#00ff41;
}

.stTextInput input{
background:#021006 !important;
color:#00ff41 !important;
border:1px solid #00ff41 !important;
font-size:22px !important;
padding:14px !important;
}

.stSelectbox > div > div{
background:#021006 !important;
color:#00ff41 !important;
border:1px solid #00ff41 !important;
font-size:20px !important;
}

.stButton > button{
background:linear-gradient(90deg,#003b0f,#00ff41) !important;
color:black !important;
font-weight:bold;
border-radius:12px !important;
font-size:20px !important;
padding:14px 24px !important;
}

</style>
""", unsafe_allow_html=True)


# ── Tab Styling ─────────────────────────
st.markdown("""
<style>

[data-baseweb="tab"]{
font-size:24px !important;
color:#7bffb5 !important;
padding:12px 26px !important;
transition:all 0.25s ease;
}

[aria-selected="true"]{
color:#00ff41 !important;
border-bottom:3px solid #00ff41 !important;
text-shadow:
0 0 6px #00ff41,
0 0 14px #00ff41,
0 0 28px #00ff41;
}

[data-baseweb="tab"]:hover{
color:#00ff41 !important;
text-shadow:
0 0 6px #00ff41,
0 0 12px #00ff41;
}

</style>
""", unsafe_allow_html=True)


# ── UI Header ───────────────────────────
st.title("ONION_RINGS Breach Monitoring")
st.write("Scan credentials using threat intelligence APIs.")


# ── Tabs ────────────────────────────────
tab_email, tab_password, tab_vpn, tab_api, tab_phone = st.tabs(
["Email","Password","VPN / IP","Domain","Phone"]
)

# ── Email Tab ───────────────────────────
with tab_email:

    email_input = st.text_input("Enter Email Address")

    if st.button("Scan Email"):

        if email_input:

            with st.spinner("Checking breach databases..."):

                result = check_email(email_input)

                store_scan(email=email_input)

                if result.get("result"):
                    st.error("⚠ Email found in breach databases")
                    st.json(result["result"])
                else:
                    st.success("No breaches detected")



# ── Password Tab ────────────────────────
with tab_password:

    pwd_input = st.text_input("Enter Password", type="password")

    if st.button("Scan Password"):

        if pwd_input:

            with st.spinner("Checking password leaks..."):

                result = check_password(pwd_input)

                store_scan(password=pwd_input)

                if result["breached"]:
                    st.error(f"⚠ Password leaked {result['count']} times")
                else:
                    st.success("Password not found in breach databases")


# ── VPN / IP Tab ────────────────────────
with tab_vpn:

    vpn_input = st.text_input("Enter VPN / IP Address")

    if st.button("Scan IP"):

        if vpn_input:

            with st.spinner("Checking IP reputation..."):

                data = check_vpn_ip(vpn_input)

                store_scan(vpn=vpn_input)

                if data["abuse_score"] > 50:
                    st.error(f"⚠ High abuse score: {data['abuse_score']}")
                else:
                    st.success("IP appears safe")

                st.json(data)


# ── Domain / API Tab ────────────────────
with tab_api:

    api_input = st.text_input("Enter Domain")

    if st.button("Scan Domain"):

        if api_input:

            with st.spinner("Checking domain reputation..."):

                data = check_domain(api_input)

                store_scan(api=api_input)

                if data["malicious"]:
                    st.error("⚠ Domain flagged by security engines")
                else:
                    st.success("No malicious detections")

                st.write(data)


# ── Phone Tab ───────────────────────────
with tab_phone:

    st.markdown("### 📡 Phone Number Validator")

    # Step 1 — Country Selection
    st.markdown("**Step 1 — Select Country**")
    selected_country_label = st.selectbox(
        "Choose Country",
        options=list(COUNTRY_CODES.keys()),
        index=0  # defaults to India
    )

    selected_country = COUNTRY_CODES[selected_country_label]
    country_code     = selected_country["code"]   # e.g. "IN"
    dial_code        = selected_country["dial"]    # e.g. "+91"

    # Show selected country info
    st.markdown(
        f"""
        <div style='
            background:#021006;
            border:1px solid #00ff41;
            border-radius:8px;
            padding:10px 18px;
            margin-bottom:12px;
            font-size:18px;
        '>
             Country Code: <b style='color:#00ff41'>{country_code}</b>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Dial Code: <b style='color:#00ff41'>{dial_code}</b>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Step 2 — Phone Number Input
    st.markdown("**Step 2 — Enter Phone Number**")
    st.caption(f"Enter without country code — we will add {dial_code} automatically")

    phone_input = st.text_input(
        "Phone Number",
        placeholder=f"e.g. 9876543210"
    )

    # Show full number preview
    if phone_input:
        full_number = f"{dial_code}{phone_input}".replace("+", "")
        st.markdown(
            f"""
            <div style='
                background:#021006;
                border:1px solid #00ff41;
                border-radius:8px;
                padding:10px 18px;
                margin-bottom:12px;
                font-size:18px;
            '>
                 Full Number: <b style='color:#00ff41'>{full_number}</b>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Step 3 — Scan Button
    if st.button("Scan Phone"):

        if phone_input:

            full_number = f"{dial_code}{phone_input}"

            with st.spinner(f"Validating {full_number} for {selected_country_label}..."):

                # Pass full number with country code to backend
                data = check_phone(full_number, country_code=country_code)

                store_scan(phone=full_number)

                # ── Results Display ──────────────
                st.markdown("### Results")

                if data.get("valid"):
                    st.success(f"Valid phone number in {selected_country_label}")
                else:
                    st.error(f"Invalid")

                # ── Detail Cards ─────────────────
                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric(
                        label="Line Type",
                        value=data.get("line_type", data.get("type", "Unknown")).upper()
                    )

                with col2:
                    st.metric(
                        label="Carrier",
                        value=data.get("carrier", "Unknown")
                    )

                with col3:
                    fraud = data.get("fraud_score", 0)
                    st.metric(
                        label="Fraud Score",
                        value=f"{fraud}/100",
                        delta="High Risk" if fraud > 75 else "Low Risk",
                        delta_color="inverse"
                    )

                # ── Risk Assessment ───────────────
                st.markdown("### Risk Assessment")

                line_type = data.get("line_type", data.get("type", "")).upper()
                fraud_score = data.get("fraud_score", 0)

                if not data.get("valid"):
                    st.error(" INVALID NUMBER — Does not exist in this country")
                elif fraud_score > 75:
                    st.error(f" CRITICAL — Fraud score {fraud_score}/100")
                elif line_type == "VOIP":
                    st.warning(" HIGH RISK — VOIP number (commonly used by attackers)")
                elif fraud_score > 50:
                    st.warning(f" MEDIUM RISK — Moderate fraud score {fraud_score}/100")
                else:
                    st.success(" LOW RISK — Appears legitimate")

                # ── Full JSON Response ────────────
                with st.expander("View Full API Response"):
                    st.json(data)

        else:
            st.warning("Please enter a phone number first")


# ── Emergency Controls ──────────────────
st.markdown("---")
st.subheader("Emergency Controls")

if st.button("WIPE ALL DATA", type="primary"):
    wipe_database()
    st.success("All stored scan history wiped.")


# ── Footer ──────────────────────────────
st.caption(
    f"Team ONION_RINGS | SYSTEM DATE & TIME: {datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%d-%m-%Y %H:%M:%S IST')}"
)
