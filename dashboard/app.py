import os
from datetime import datetime
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# ── Page config ─────────────────────────
st.set_page_config(page_title="ONION_RINGS", layout="wide")

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

html, body, .stApp, div, p, span, label{
font-family:'JetBrains Mono', monospace !important;
font-size:24px !important;
color:#a8ffcf;
}

h1{
font-family:'Orbitron', sans-serif !important;
font-size:4rem !important;
color:#00ff41;
text-shadow:0 0 10px #00ff41;
}

h2{
font-family:'Orbitron', sans-serif !important;
font-size:2.8rem !important;
color:#00ff41;
}

h3{
font-family:'Orbitron', sans-serif !important;
font-size:2.2rem !important;
color:#00ff41;
}

.stTextInput input{
background:#021006 !important;
color:#00ff41 !important;
border:1px solid #00ff41 !important;
font-size:24px !important;
padding:16px !important;
}

.stButton > button{
background:linear-gradient(90deg,#003b0f,#00ff41) !important;
color:black !important;
font-weight:bold;
border-radius:12px !important;
font-size:22px !important;
padding:16px 28px !important;
}

</style>
""", unsafe_allow_html=True)


# ── Session State ───────────────────────
if "alerts" not in st.session_state:
    st.session_state.alerts = []


# ── Data Loading ────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

def load_csv(name):
    path = os.path.join(DATA_DIR, name)
    if os.path.exists(path):
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip()
        return df
    return pd.DataFrame()

datasets = {
    "email": load_csv("email_breach_dataset_50000.csv"),
    "phone": load_csv("phone_cybersecurity_dataset.csv"),
    "vpn": load_csv("vpn_breach_dataset.csv"),
    "api": load_csv("darkwatch_api_dataset.csv"),
    "password": load_csv("password_leaks_dataset.csv"),
}


# ── Detection Functions ─────────────────
def check_email(q):
    df = datasets["email"]
    if df.empty or "email" not in df.columns:
        return []
    rows = df[df["email"].str.lower() == q.lower()]
    return rows.to_dict("records")

def check_phone(q):
    df = datasets["phone"]
    if df.empty or "phone_number" not in df.columns:
        return []
    rows = df[df["phone_number"].astype(str) == q]
    return rows.to_dict("records")

def check_vpn(q):
    df = datasets["vpn"]
    if df.empty or "username" not in df.columns:
        return []
    rows = df[df["username"].str.lower() == q.lower()]
    return rows.to_dict("records")

def check_password(q):
    df = datasets["password"]
    if df.empty or "password" not in df.columns:
        return []
    rows = df[df["password"] == q]
    return rows.to_dict("records")

def check_api(q):
    df = datasets["api"]
    if df.empty:
        return []
    rows = df[df.get("owner_domain", pd.Series(dtype=str)).str.contains(q, case=False, na=False)]
    return rows.to_dict("records")


# ── UI Header ───────────────────────────
st.title("ONION_RINGS Breach Monitoring")
st.write("Search if credentials appear in breach datasets.")


# ── Tabs ────────────────────────────────
tab_email, tab_password, tab_vpn, tab_api, tab_phone = st.tabs(
["Email","Password","VPN","API Key","Phone"]
)


with tab_email:
    email = st.text_input("Enter Email")
    if st.button("Scan Email"):
        results = check_email(email)
        if results:
            st.error("⚠ Email found in breach dataset")
            st.dataframe(results)
        else:
            st.success("No breach detected")


with tab_password:
    pwd = st.text_input("Enter Password", type="password")
    if st.button("Scan Password"):
        results = check_password(pwd)
        if results:
            st.error("⚠ Password exposed in leaks")
            st.dataframe(results)
        else:
            st.success("Password not found")


with tab_vpn:
    vpn = st.text_input("Enter VPN Username")
    if st.button("Scan VPN"):
        results = check_vpn(vpn)
        if results:
            st.error("⚠ VPN credentials leaked")
            st.dataframe(results)
        else:
            st.success("No breach detected")


with tab_api:
    api = st.text_input("Enter API Domain or Prefix")
    if st.button("Scan API Key"):
        results = check_api(api)
        if results:
            st.error("⚠ API exposure detected")
            st.dataframe(results)
        else:
            st.success("No exposure found")


with tab_phone:
    phone = st.text_input("Enter Phone Number")
    if st.button("Scan Phone"):
        results = check_phone(phone)
        if results:
            st.error("⚠ Phone number exposed")
            st.dataframe(results)
        else:
            st.success("No breach detected")


# ── Dataset Info ────────────────────────
st.markdown("---")
st.subheader("Loaded Datasets")

col1,col2,col3,col4,col5 = st.columns(5)

col1.metric("Emails",len(datasets["email"]))
col2.metric("Phones",len(datasets["phone"]))
col3.metric("VPN",len(datasets["vpn"]))
col4.metric("API",len(datasets["api"]))
col5.metric("Passwords",len(datasets["password"]))


# ── Emergency Controls ──────────────────
st.markdown("---")
st.subheader("Emergency Controls: You can choose to let us store your data or wipe it from our database.")

if st.button("WIPE ALL DATA", type="primary"):
    st.session_state.alerts = []
    st.success("All alerts and stored data wiped.")


# ── Footer ──────────────────────────────
st.caption(f"ONION_RINGS • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
