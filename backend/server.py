from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import logging
import uuid
import bcrypt
import jwt
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional
from datetime import datetime, timezone, timedelta

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# ---------- Env ----------
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "1440"))
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")

# ---------- DB ----------
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# ---------- App ----------
app = FastAPI(title="CyberShield Detection API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("cybershield")


# ---------- Models ----------
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: str = Field(min_length=1, max_length=80)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: EmailStr
    name: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class ProfileInput(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    platform: str = Field(default="generic")
    profile_url: Optional[str] = None
    account_age_days: int = Field(ge=0, le=20000)
    followers: int = Field(ge=0)
    following: int = Field(ge=0)
    posts_count: int = Field(ge=0)
    has_profile_picture: bool = True
    has_bio: bool = True
    is_verified: bool = False
    posting_frequency_per_day: float = Field(ge=0, le=500)
    messages: Optional[str] = ""  # newline-separated sample messages


class RiskFactor(BaseModel):
    label: str
    score: int  # 0-100 contribution
    description: str


class ScanResult(BaseModel):
    id: str
    user_id: str
    username: str
    platform: str
    profile_url: Optional[str] = None
    risk_score: int
    classification: str  # Safe | Medium Risk | High Risk
    factors: List[RiskFactor]
    toxic_flags: List[str]
    repeated_messages: List[str]
    ai_insight: str
    alert: Optional[str] = None
    created_at: datetime


# ---------- Auth utils ----------
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ---------- Risk engine ----------
TOXIC_KEYWORDS = [
    "kill", "hate", "stalk", "stalking", "threat", "die", "ugly",
    "loser", "bitch", "slut", "whore", "idiot", "stupid", "dumb",
    "shut up", "i know where you live", "i'll find you", "watching you",
    "follow you", "revenge", "expose you", "fuck", "harass",
]

SUSPICIOUS_PATTERNS = [
    r"\b(click|visit|check)\s+(this|my)?\s*(link|bio)\b",
    r"https?://\S+",
    r"send\s+me\s+(money|crypto|btc|eth)",
    r"dm\s+me",
    r"i\s+love\s+you",
    r"meet\s+me",
]


def compute_rule_based(data: ProfileInput) -> dict:
    factors: List[RiskFactor] = []
    score = 0

    # Account age
    if data.account_age_days < 30:
        s = 25
        factors.append(RiskFactor(label="New account", score=s,
                                  description=f"Account only {data.account_age_days} days old"))
        score += s
    elif data.account_age_days < 180:
        s = 10
        factors.append(RiskFactor(label="Young account", score=s,
                                  description=f"Account {data.account_age_days} days old"))
        score += s

    # Follower/Following ratio
    ratio = data.followers / data.following if data.following > 0 else (data.followers or 1)
    if data.following > 500 and ratio < 0.1:
        s = 20
        factors.append(RiskFactor(label="Follow spam pattern", score=s,
                                  description=f"Follows {data.following} but has only {data.followers} followers"))
        score += s
    elif data.following > 1000 and ratio < 0.3:
        s = 10
        factors.append(RiskFactor(label="Unbalanced social graph", score=s,
                                  description="Following many, few followers"))
        score += s

    # Posting frequency
    if data.posting_frequency_per_day > 50:
        s = 20
        factors.append(RiskFactor(label="Abnormal activity spike", score=s,
                                  description=f"{data.posting_frequency_per_day} posts/day indicates bot-like activity"))
        score += s
    elif data.posting_frequency_per_day > 20:
        s = 10
        factors.append(RiskFactor(label="High activity", score=s,
                                  description=f"{data.posting_frequency_per_day} posts/day is unusually high"))
        score += s

    # Low posts, high follow
    if data.posts_count < 3 and data.following > 200:
        s = 15
        factors.append(RiskFactor(label="Empty profile with many follows", score=s,
                                  description="Few posts but aggressive following behavior"))
        score += s

    # Profile completeness
    if not data.has_profile_picture:
        s = 10
        factors.append(RiskFactor(label="No profile picture", score=s,
                                  description="Missing avatar is a common fake-profile signal"))
        score += s
    if not data.has_bio:
        s = 5
        factors.append(RiskFactor(label="No bio", score=s, description="Empty bio reduces trust"))
        score += s

    if data.is_verified:
        s = -15
        factors.append(RiskFactor(label="Verified account", score=s,
                                  description="Platform-verified — strong trust signal"))
        score += s

    # Messages analysis
    msgs = [m.strip() for m in (data.messages or "").split("\n") if m.strip()]
    toxic_flags: List[str] = []
    repeated: List[str] = []

    if msgs:
        lower_msgs = [m.lower() for m in msgs]
        # repeated
        seen = {}
        for m in lower_msgs:
            seen[m] = seen.get(m, 0) + 1
        for m, c in seen.items():
            if c >= 2:
                repeated.append(f"({c}x) {m[:80]}")
        if repeated:
            s = min(20, 5 * len(repeated))
            factors.append(RiskFactor(label="Repeated messages", score=s,
                                      description=f"{len(repeated)} message(s) sent repeatedly"))
            score += s

        # toxic keywords
        for kw in TOXIC_KEYWORDS:
            for m in lower_msgs:
                if kw in m:
                    toxic_flags.append(kw)
                    break
        if toxic_flags:
            s = min(30, 6 * len(toxic_flags))
            factors.append(RiskFactor(label="Toxic language detected", score=s,
                                      description=f"Found terms: {', '.join(toxic_flags[:6])}"))
            score += s

        # suspicious patterns
        pattern_hits = 0
        for p in SUSPICIOUS_PATTERNS:
            for m in lower_msgs:
                if re.search(p, m):
                    pattern_hits += 1
                    break
        if pattern_hits:
            s = min(20, 5 * pattern_hits)
            factors.append(RiskFactor(label="Suspicious patterns", score=s,
                                      description=f"{pattern_hits} suspicious phrasing pattern(s) (links, DM requests, money)"))
            score += s

    score = max(0, min(100, score))
    return {
        "score": score,
        "factors": factors,
        "toxic_flags": list(dict.fromkeys(toxic_flags)),
        "repeated": repeated,
    }


def classify(score: int) -> str:
    if score >= 65:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    return "Safe"


async def ai_insight(data: ProfileInput, rule_result: dict) -> str:
    """Use Claude Sonnet 4.5 for deeper NLP analysis."""
    if not EMERGENT_LLM_KEY:
        return "AI insight unavailable (no LLM key configured)."
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage

        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"scan-{uuid.uuid4()}",
            system_message=(
                "You are a cybersecurity analyst specializing in fake-profile and cyberstalker detection. "
                "Given structured profile signals, return a SHORT (2-4 sentences) expert analysis. "
                "Be concrete, mention the strongest red flags, and end with one actionable recommendation. "
                "Never include JSON or markdown code fences — plain prose only."
            ),
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")

        msgs_sample = (data.messages or "").strip().replace("\n", " | ")[:500] or "(no messages provided)"
        prompt = (
            f"Profile: @{data.username} on {data.platform}\n"
            f"Account age: {data.account_age_days} days | Followers: {data.followers} | "
            f"Following: {data.following} | Posts: {data.posts_count} | "
            f"Posts/day: {data.posting_frequency_per_day} | Verified: {data.is_verified} | "
            f"Pic: {data.has_profile_picture} | Bio: {data.has_bio}\n"
            f"Sample messages: {msgs_sample}\n"
            f"Rule-based score: {rule_result['score']}/100\n"
            f"Detected factors: {', '.join(f.label for f in rule_result['factors']) or 'none'}\n"
            f"Toxic flags: {', '.join(rule_result['toxic_flags']) or 'none'}\n\n"
            "Write the expert analysis now."
        )
        resp = await chat.send_message(UserMessage(text=prompt))
        return str(resp).strip()
    except Exception as e:
        logger.warning(f"AI insight failed: {e}")
        return "AI insight temporarily unavailable. Falling back to rule-based signals."


# ---------- Routes ----------
@api_router.get("/")
async def root():
    return {"service": "CyberShield", "status": "online"}


@api_router.post("/auth/register", response_model=TokenResponse)
async def register(body: UserRegister):
    existing = await db.users.find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    doc = {
        "id": user_id,
        "email": body.email.lower(),
        "name": body.name,
        "password_hash": hash_password(body.password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(doc)
    token = create_token(user_id)
    return TokenResponse(
        access_token=token,
        user=UserPublic(id=user_id, email=body.email.lower(), name=body.name),
    )


@api_router.post("/auth/login", response_model=TokenResponse)
async def login(body: UserLogin):
    user = await db.users.find_one({"email": body.email.lower()}, {"_id": 0})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(user["id"])
    return TokenResponse(
        access_token=token,
        user=UserPublic(id=user["id"], email=user["email"], name=user["name"]),
    )


@api_router.get("/auth/me", response_model=UserPublic)
async def me(user: dict = Depends(get_current_user)):
    return UserPublic(id=user["id"], email=user["email"], name=user["name"])


@api_router.post("/scan", response_model=ScanResult)
async def scan_profile(data: ProfileInput, user: dict = Depends(get_current_user)):
    rule = compute_rule_based(data)
    insight = await ai_insight(data, rule)
    score = rule["score"]
    cls = classify(score)
    alert = None
    if cls == "High Risk":
        alert = f"High risk — @{data.username} may be a fake account or cyberstalker. Block and report."
    elif cls == "Medium Risk":
        alert = f"Caution — @{data.username} shows suspicious patterns. Review interactions carefully."

    scan = ScanResult(
        id=str(uuid.uuid4()),
        user_id=user["id"],
        username=data.username,
        platform=data.platform,
        profile_url=data.profile_url,
        risk_score=score,
        classification=cls,
        factors=rule["factors"],
        toxic_flags=rule["toxic_flags"],
        repeated_messages=rule["repeated"],
        ai_insight=insight,
        alert=alert,
        created_at=datetime.now(timezone.utc),
    )
    doc = scan.model_dump()
    doc["created_at"] = doc["created_at"].isoformat()
    await db.scans.insert_one(doc)
    return scan


@api_router.get("/scans", response_model=List[ScanResult])
async def list_scans(user: dict = Depends(get_current_user)):
    cursor = db.scans.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).limit(200)
    items = await cursor.to_list(200)
    for it in items:
        if isinstance(it.get("created_at"), str):
            it["created_at"] = datetime.fromisoformat(it["created_at"])
    return items


@api_router.get("/scans/stats")
async def stats(user: dict = Depends(get_current_user)):
    cursor = db.scans.find({"user_id": user["id"]}, {"_id": 0, "risk_score": 1, "classification": 1, "created_at": 1})
    items = await cursor.to_list(500)
    total = len(items)
    safe = sum(1 for x in items if x["classification"] == "Safe")
    med = sum(1 for x in items if x["classification"] == "Medium Risk")
    high = sum(1 for x in items if x["classification"] == "High Risk")
    avg = round(sum(x["risk_score"] for x in items) / total, 1) if total else 0
    trend = sorted(items, key=lambda x: x["created_at"])[-10:]
    trend_out = [{"created_at": x["created_at"], "risk_score": x["risk_score"]} for x in trend]
    return {
        "total": total,
        "safe": safe,
        "medium": med,
        "high": high,
        "avg_score": avg,
        "trend": trend_out,
    }


@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, user: dict = Depends(get_current_user)):
    res = await db.scans.delete_one({"id": scan_id, "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}


# ---------- App wiring ----------
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
