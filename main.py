from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional
import hashlib
import re
import os

app = FastAPI(title="Password Strength Analyzer", version="1.0.0")

# Rate limiting (simple in-memory)
from datetime import datetime, timedelta
rate_limits = {}

def rate_limit(request: Request):
    api_key = request.headers.get("X-API-Key", "anonymous")
    now = datetime.now()
    
    key = f"{api_key}:{now.strftime('%Y-%m-%d-%H')}"
    if key not in rate_limits:
        rate_limits[key] = 0
    rate_limits[key] += 1
    
    if rate_limits[key] > 1000:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return

class PasswordRequest(BaseModel):
    password: str

class StrengthResult(BaseModel):
    score: int
    verdict: str
    entropy: float
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    suggestions: list

class BreachCheckRequest(BaseModel):
    password: str

class BreachResult(BaseModel):
    breached: bool
    message: str

def calculate_entropy(password: str) -> float:
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32
    
    if charset_size == 0:
        return 0
    return len(password) * (charset_size.bit_length() - 1)

def get_strength_verdict(score: int) -> str:
    if score < 3:
        return "Very Weak"
    elif score < 5:
        return "Weak"
    elif score < 7:
        return "Moderate"
    elif score < 9:
        return "Strong"
    else:
        return "Very Strong"

def generate_suggestions(password: str, score: int) -> list:
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add uppercase letters")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add lowercase letters")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add numbers")
    if not re.search(r'[^a-zA-Z0-9]', password):
        suggestions.append("Add special characters (!@#$%^&* etc)")
    if score < 7:
        suggestions.append("Avoid common patterns like 'password123'")
    return suggestions

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/analyze")
async def analyze_password(request: PasswordRequest, _: None = Depends(rate_limit)):
    if not request.password:
        raise HTTPException(status_code=400, detail="Password required")
    
    password = request.password
    entropy = calculate_entropy(password)
    
    length = len(password)
    length_score = min(length // 2, 5)
    entropy_score = min(int(entropy / 10), 5)
    score = min((length_score + entropy_score) // 2, 10)
    
    result = StrengthResult(
        score=score,
        verdict=get_strength_verdict(score),
        entropy=round(entropy, 2),
        length=length,
        has_uppercase=bool(re.search(r'[A-Z]', password)),
        has_lowercase=bool(re.search(r'[a-z]', password)),
        has_digits=bool(re.search(r'[0-9]', password)),
        has_special=bool(re.search(r'[^a-zA-Z0-9]', password)),
        suggestions=generate_suggestions(password, score)
    )
    return result

@app.post("/check-breach")
async def check_breach(request: BreachCheckRequest, _: None = Depends(rate_limit)):
    password = request.password
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    try:
        import urllib.request
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "Hermes-Password-API"})
        resp = urllib.request.urlopen(req, timeout=10)
        hashes = resp.read().decode().split('\r\n')
        
        for line in hashes:
            parts = line.split(':')
            if parts[0] == suffix:
                count = int(parts[1])
                return BreachResult(breached=True, message=f"Password found in {count:,} breaches")
        
        return BreachResult(breached=False, message="Password not found in known breaches")
    except Exception as e:
        return BreachResult(breached=False, message="Could not check breaches (offline mode)")

try:
    from mangum import Mangum
    handler = Mangum(app, lifespan="off")
except ImportError:
    pass