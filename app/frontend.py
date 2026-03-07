import sqlite3
import hashlib
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_API_KEY = os.getenv("EMAIL_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
PHONE_API_KEY = os.getenv("PHONE_API_KEY")

# -------------------------------
# DATABASE
# -------------------------------

DB_FILE = "onion_rings.db"


def init_db():

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        password_hash TEXT,
        vpn_ip TEXT,
        api_domain TEXT,
        phone TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def store_scan(email=None, password=None, vpn=None, api=None, phone=None):

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    password_hash = None

    if password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()

    c.execute("""
    INSERT INTO scans(email,password_hash,vpn_ip,api_domain,phone,timestamp)
    VALUES(?,?,?,?,?,?)
    """,
              (
                  email,
                  password_hash,
                  vpn,
                  api,
                  phone,
                  datetime.now(ZoneInfo("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
              ))

    conn.commit()
    conn.close()

# -------------------------------
# EMAIL BREACH CHECK
# -------------------------------

import requests


def check_email(email):

    url = "https://breachdirectory.p.rapidapi.com/"

    querystring = {
        "func": "auto",
        "term": email
    }

    headers = {
        "X-RapidAPI-Key": EMAIL_API_KEY,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
    }

    r = requests.get(url, headers=headers, params=querystring)

    data = r.json()

    return data

# -------------------------------
# PASSWORD BREACH CHECK
# -------------------------------

def check_password(password):

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()

    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    r = requests.get(url)

    hashes = r.text.splitlines()

    for line in hashes:

        h, count = line.split(":")

        if h == suffix:
            return {
                "breached": True,
                "count": int(count)
            }

    return {
        "breached": False,
        "count": 0
    }


# -------------------------------
# VPN / IP CHECK
# -------------------------------

def check_vpn_ip(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    r = requests.get(url, headers=headers, params=params)

    data = r.json()

    return {
        "ip": ip,
        "abuse_score": data["data"]["abuseConfidenceScore"],
        "country": data["data"]["countryCode"],
        "isp": data["data"]["isp"]
    }


# -------------------------------
# DOMAIN / API CHECK
# -------------------------------

def check_domain(domain):

    url = "https://www.virustotal.com/vtapi/v2/domain/report"

    params = {
        "apikey": VT_API_KEY,
        "domain": domain
    }

    r = requests.get(url, params=params)

    data = r.json()

    malicious = False

    if data.get("detected_urls"):
        malicious = True

    return {
        "domain": domain,
        "malicious": malicious,
        "detections": len(data.get("detected_urls", []))
    }


# -------------------------------
# PHONE VALIDATION
# -------------------------------

import requests

def check_phone(phone):

    url = "https://phonevalidation.abstractapi.com/v1/"

    params = {
        "api_key": PHONE_API_KEY,
        "phone": phone
    }

    r = requests.get(url, params=params)
    data = r.json()

    return {
        "phone": data.get("phone", phone),
        "valid": data.get("valid", False),
        "country": data.get("country", {}).get("name") if data.get("country") else None,
        "carrier": data.get("carrier"),
        "type": data.get("type")
    }

# -------------------------------
# DATABASE UTILS
# -------------------------------

def get_scan_history():

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    rows = c.execute("""
    SELECT email,password_hash,vpn_ip,api_domain,phone,timestamp
    FROM scans
    ORDER BY id DESC
    """).fetchall()

    conn.close()

    return rows


def wipe_database():

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("DELETE FROM scans")

    conn.commit()
    conn.close()


# -------------------------------
# INITIALIZE DATABASE
# -------------------------------

init_db()
