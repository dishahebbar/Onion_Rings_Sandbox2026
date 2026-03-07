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

def check_phone(phone_number, country_code=None):
    try:
        url = f"https://ipqualityscore.com/api/json/phone/{PHONE_API_KEY}/{phone_number}?country={country_code}"
        
        response = requests.get(url)
        data = response.json()
        
        return {
            "valid":       data.get("valid", False),
            "fraud_score": data.get("fraud_score", 0),
            "line_type":   data.get("line_type", "Unknown"),
            "carrier":     data.get("carrier", "Unknown"),
            "country":     data.get("country_code", country_code),
            "active":      data.get("active", False),
            "risky":       data.get("risky", False),
        }

    except Exception as e:
        return {
            "valid":       False,
            "fraud_score": 0,
            "line_type":   "Unknown",
            "carrier":     "Unknown",
            "country":     country_code,
            "error":       str(e)
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

# -------------------------------
# DATABASE UTILS
# -------------------------------
import hashlib

def count_user_records(identifier):

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    password_hash = hashlib.sha256(identifier.encode()).hexdigest()

    query = """
    SELECT COUNT(*) FROM scans
    WHERE email = ?
       OR phone = ?
       OR vpn_ip = ?
       OR api_domain = ?
       OR password_hash = ?
    """

    result = c.execute(
        query,
        (identifier, identifier, identifier, identifier, password_hash)
    ).fetchone()

    conn.close()

    return result[0]

def delete_user_data(email=None, phone=None, vpn=None, domain=None, password=None):

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    password_hash = None
    if password:
        password_hash = hashlib.sha256(password.encode()).hexdigest()

    query = """
    DELETE FROM scans
    WHERE email = ?
       OR phone = ?
       OR vpn_ip = ?
       OR api_domain = ?
       OR password_hash = ?
    """

    c.execute(query, (email, phone, vpn, domain, password_hash))

    conn.commit()
    conn.close()


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
