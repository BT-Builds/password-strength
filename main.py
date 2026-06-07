import hashlib
import re
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from mangum import Mangum

app = FastAPI(
    title="Password Strength API",
    description="Check password security and get actionable recommendations",
    version="1.0.0"
)
# === BT Builds Standard Middleware (auto-injected) ===
from fastapi.middleware.cors import CORSMiddleware as _BTCors
app.add_middleware(_BTCors, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], expose_headers=["X-RateLimit-Limit","X-RateLimit-Remaining","X-RateLimit-Reset"])

@app.middleware("http")
async def _bt_add_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Powered-By"] = "btbuilds"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# API Key auth
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

def get_api_key(key: str = Security(API_KEY_HEADER)):
    if not key:
        raise HTTPException(status_code=401, detail="API key required")
    return key

# In-memory rate limiting
rate_limit_store = {}

def rate_limit(api_key: str = Depends(get_api_key)):
    import time
    key = f"rate_{api_key}"
    current_time = int(time.time())
    minute_ago = current_time - 60
    
    if key not in rate_limit_store:
        rate_limit_store[key] = []
    
    rate_limit_store[key] = [t for t in rate_limit_store[key] if t > minute_ago]
    
    if len(rate_limit_store[key]) >= 100:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (100/min)")
    
    rate_limit_store[key].append(current_time)
    return api_key

# Common weak passwords
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "password1",
    "password123", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "login", "princess", "football",
    "iloveyou", "trustno1", "shadow", "sunshine", "ashley",
    "bailey", "passw0rd", "baseball", "tigger", "hunter"
}

class PasswordCheck(BaseModel):
    password: str

class PasswordResponse(BaseModel):
    score: int
    strength: str
    length: int
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    has_common_pattern: bool
    is_common_password: bool
    entropy_bits: int
    recommendations: list[str]

@app.get("/health")
def health():
    return {"status": "ok", "service": "password-strength-api"}

@app.post("/check", dependencies=[Depends(rate_limit)])
def check_password(data: PasswordCheck) -> PasswordResponse:
    password = data.password
    length = len(password)
    
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?`~\\|\\]', password))
    
    is_common = password.lower() in {p.lower() for p in COMMON_PASSWORDS}
    
    patterns = [
        (r'(\d)\1{2,}', "repeated digits"),
        (r'([a-zA-Z])\1{2,}', "repeated letters"),
        (r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efgh)', "sequential pattern"),
        (r'(qwerty|asdf|zxcv)', "keyboard pattern")
    ]
    has_pattern = any(re.search(p, password.lower()) for p, _ in patterns)
    
    charset_size = sum([
        26 if has_lower else 0,
        26 if has_upper else 0,
        10 if has_digit else 0,
        20 if has_special else 0
    ])
    entropy = int(length * (charset_size.bit_length() or 1)) if charset_size > 0 else 0
    
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if has_upper and has_lower and has_digit:
        score += 1
    if has_special:
        score += 1
    
    if is_common or has_pattern:
        score = max(0, score - 2)
    
    strength_map = {0: "very_weak", 1: "weak", 2: "moderate", 3: "strong", 4: "very_strong"}
    strength = strength_map.get(score, "weak")
    
    recommendations = []
    if length < 12:
        recommendations.append("Use at least 12 characters")
    if not has_upper:
        recommendations.append("Add uppercase letters")
    if not has_lower:
        recommendations.append("Add lowercase letters")
    if not has_digit:
        recommendations.append("Add numbers")
    if not has_special:
        recommendations.append("Add special characters (!@#$%^&*)")
    if has_pattern:
        recommendations.append("Avoid repeated or sequential patterns")
    if is_common:
        recommendations.append("This is a commonly used password - avoid it completely")
    
    return PasswordResponse(
        score=score, strength=strength, length=length,
        has_uppercase=has_upper, has_lowercase=has_lower,
        has_digits=has_digit, has_special=has_special,
        has_common_pattern=has_pattern, is_common_password=is_common,
        entropy_bits=entropy, recommendations=recommendations
    )

@app.post("/hash")
def hash_password(data: PasswordCheck, api_key: str = Security(get_api_key)):
    return {"hash": hashlib.sha256(data.password.encode()).hexdigest(), "algorithm": "sha256"}

# Lambda handler for Vercel
handler = Mangum(app)