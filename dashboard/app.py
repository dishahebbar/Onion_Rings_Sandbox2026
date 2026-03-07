import os
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components


# ── Page config ─────────────────────────
st.set_page_config(page_title="ONION_RINGS", layout="wide")


# ── Database Setup ──────────────────────
DB_FILE = "onion_rings.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS user_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        password TEXT,
        vpn TEXT,
        api TEXT,
        phone TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()


def store_user_data(email=None, password=None, vpn=None, api=None, phone=None):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    INSERT INTO user_scans(email,password,vpn,api,phone,timestamp)
    VALUES(?,?,?,?,?,?)
    """,
    (
        email,
        password,
        vpn,
        api,
        phone,
        datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def wipe_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM user_scans")
    conn.commit()
    conn.close()


def get_stored_values(column):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    query = f"SELECT DISTINCT {column} FROM user_scans WHERE {column} IS NOT NULL AND {column} != ''"
    rows = c.execute(query).fetchall()

    conn.close()

    return [r[0] for r in rows]


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

    email_history = get_stored_values("email")

    email_select = st.selectbox("Previous Emails", [""] + email_history)

    new_email = st.text_input("Or Enter Email")

    final_email = new_email if new_email else email_select

    if st.button("Scan Email"):

        if final_email:
            store_user_data(email=final_email)

            results = check_email(final_email)

            if results:
                st.error("⚠ Email found in breach dataset")
                st.dataframe(results)
            else:
                st.success("No breach detected")


with tab_password:

    pwd_history = get_stored_values("password")

    pwd_select = st.selectbox("Previous Passwords", [""] + pwd_history)

    pwd_input = st.text_input("Or Enter Password", type="password")

    final_pwd = pwd_input if pwd_input else pwd_select

    if st.button("Scan Password"):

        if final_pwd:
            store_user_data(password=final_pwd)

            results = check_password(final_pwd)

            if results:
                st.error("⚠ Password exposed in leaks")
                st.dataframe(results)
            else:
                st.success("Password not found")


with tab_vpn:

    vpn_history = get_stored_values("vpn")

    vpn_select = st.selectbox("Previous VPN Users", [""] + vpn_history)

    vpn_input = st.text_input("Or Enter VPN Username")

    final_vpn = vpn_input if vpn_input else vpn_select

    if st.button("Scan VPN"):

        if final_vpn:
            store_user_data(vpn=final_vpn)

            results = check_vpn(final_vpn)

            if results:
                st.error("⚠ VPN credentials leaked")
                st.dataframe(results)
            else:
                st.success("No breach detected")


with tab_api:

    api_history = get_stored_values("api")

    api_select = st.selectbox("Previous API Domains", [""] + api_history)

    api_input = st.text_input("Or Enter API Domain")

    final_api = api_input if api_input else api_select

    if st.button("Scan API Key"):

        if final_api:
            store_user_data(api=final_api)

            results = check_api(final_api)

            if results:
                st.error("⚠ API exposure detected")
                st.dataframe(results)
            else:
                st.success("No exposure found")


with tab_phone:

    phone_history = get_stored_values("phone")

    phone_select = st.selectbox("Previous Phone Numbers", [""] + phone_history)

    phone_input = st.text_input("Or Enter Phone Number")

    final_phone = phone_input if phone_input else phone_select

    if st.button("Scan Phone"):

        if final_phone:
            store_user_data(phone=final_phone)

            results = check_phone(final_phone)

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
st.subheader("Emergency Controls")

if st.button("WIPE ALL DATA", type="primary"):
    wipe_database()
    st.success("All stored user data wiped.")


# ── Footer ──────────────────────────────
st.caption(
    f"Team ONION_RINGS | SYSTEM DATE & TIME: {datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%d-%m-%Y %H:%M:%S IST')}"
)
