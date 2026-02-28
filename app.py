from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import re
from datetime import datetime
import math
import socket
import requests
import os

# ---------------- APP INIT ----------------
app = FastAPI()
# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- MongoDB (Atlas Ready) ----------------
MONGO_URI = os.environ.get("MONGO_URI")

if not MONGO_URI:
    raise Exception("MONGO_URI environment variable not set")

client = MongoClient(MONGO_URI)
db = client["phishing_ai"]
logs = db["detections"]
chat_logs = db["chat_history"]

# ---------------- MODELS ----------------
class AnalyzeRequest(BaseModel):
    email: str = ""
    sender: str = ""
    url: str = ""

class ChatRequest(BaseModel):
    message: str

# ---------------- WORD DATABASE ----------------
EMAIL_WORDS = ["verify","reset","otp","suspended","blocked","login","confirm"]
URGENCY_WORDS = ["urgent","immediately","asap","now","action required"]
FEAR_WORDS = ["deactivated","locked","warning","risk"]
SHORT_DOMAINS = ["bit.ly","tinyurl","rb.gy","t.co"]
SPOOF_PATTERNS = ["paypa1","g00gle","faceb00k","micros0ft","amaz0n"]
SUSPICIOUS_TLDS = [".ru",".tk",".xyz",".top",".gq"]
ATTACHMENT_EXT = [".exe",".scr",".zip",".rar",".html"]

# ---------------- HELPERS ----------------
def contains_url(text):
    return bool(re.search(r"https?://", text.lower()))

def contains_ip(url):
    return bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url))

def domain_entropy(domain):
    if not domain:
        return 0
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def suspicious_domain(url):
    domain = re.sub(r"https?://", "", url).split("/")[0]
    return len(domain) > 12 and domain_entropy(domain) > 3.5

def spoof_check(url):
    return any(pattern in url.lower() for pattern in SPOOF_PATTERNS)

def uppercase_pressure(text):
    return sum(1 for c in text if c.isupper()) > 12

def get_domain(url):
    if not url:
        return ""
    return re.sub(r"https?://", "", url).split("/")[0]

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_location(ip):
    if not ip:
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if response.get("status") == "success":
            return {
                "country": response.get("country"),
                "city": response.get("city"),
                "isp": response.get("isp"),
                "lat": response.get("lat"),
                "lon": response.get("lon")
            }
    except:
        return None
    return None

# ---------------- DETECTION ENGINE ----------------
def detect(email, sender, url):
    text = (email + " " + sender).lower()
    score = 0
    reasons = []
    category = "Email Phishing"

    for w in EMAIL_WORDS:
        if w in text:
            score += 10
            reasons.append(f"Keyword: {w}")

    for w in URGENCY_WORDS:
        if w in text:
            score += 10
            reasons.append("Urgency detected")

    for w in FEAR_WORDS:
        if w in text:
            score += 10
            reasons.append("Fear tactic detected")

    for ext in ATTACHMENT_EXT:
        if ext in text:
            score += 20
            reasons.append("Suspicious attachment")

    if contains_url(email) or url:
        score += 15
        category = "URL Phishing"
        reasons.append("URL detected")

    if url:
        if any(d in url.lower() for d in SHORT_DOMAINS):
            score += 20
            reasons.append("Shortened URL")
        if spoof_check(url):
            score += 25
            reasons.append("Spoofed domain")
        if suspicious_domain(url):
            score += 20
            reasons.append("Randomized domain")
        if contains_ip(url):
            score += 25
            reasons.append("IP address used")
        if any(tld in url.lower() for tld in SUSPICIOUS_TLDS):
            score += 20
            reasons.append("Suspicious TLD")

    if uppercase_pressure(email):
        score += 10
        reasons.append("Excess uppercase usage")

    confidence = min(99, score)

    if score >= 80:
        result, risk = "Phishing Detected", "Critical"
    elif score >= 60:
        result, risk = "Phishing Detected", "High"
    elif score >= 40:
        result, risk = "Suspicious", "Medium"
    elif score >= 20:
        result, risk = "Possibly Safe", "Low"
    else:
        result, risk = "Legitimate", "Safe"

    return result, risk, confidence, category, reasons

# ---------------- ROUTES ----------------
@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    result, risk, confidence, category, reasons = detect(req.email, req.sender, req.url)

    domain = get_domain(req.url)
    ip = resolve_ip(domain)
    location_data = get_location(ip)

    logs.insert_one({
        "email": req.email,
        "sender": req.sender,
        "url": req.url,
        "domain": domain,
        "resolved_ip": ip,
        "location": location_data,
        "result": result,
        "risk": risk,
        "category": category,
        "confidence": confidence,
        "reasons": reasons,
        "time": datetime.utcnow()
    })

    return {
        "result": result,
        "risk_level": risk,
        "category": category,
        "confidence": f"{confidence}%",
        "analysis": reasons,
        "domain": domain,
        "resolved_ip": ip or "Not Found",
        "location": location_data
    }

@app.get("/")
def home():
    return {"message": "API is running successfully 🚀"}