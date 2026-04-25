from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import json
import logging
import uuid
import bcrypt
import jwt
import re
import httpx
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
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet")
JINA_READER_URL = os.environ.get("JINA_READER_URL", "https://r.jina.ai")
JINA_API_KEY = os.environ.get("JINA_API_KEY", "")
APP_PUBLIC_URL = os.environ.get("APP_PUBLIC_URL", "http://localhost")
APP_NAME = os.environ.get("APP_NAME", "CyberShield")

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


class DetectInput(BaseModel):
    url: str = Field(min_length=5, max_length=500)
    platform: str = Field(default="instagram")


class RiskFactor(BaseModel):
    label: str
    score: int
    description: str


class ScanResult(BaseModel):
    id: str
    user_id: str
    username: str
    platform: str
    profile_url: Optional[str] = None
    risk_score: int
    classification: str
    factors: List[RiskFactor]
    toxic_flags: List[str]
    repeated_messages: List[str]
    contact_numbers: List[str] = []
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


# ---------- Detection pipeline (Jina + OpenRouter) ----------
def _extract_username(url: str) -> str:
    try:
        # Grab last path segment
        clean = url.strip().rstrip("/")
        parts = clean.split("/")
        candidate = parts[-1] or (parts[-2] if len(parts) > 1 else "profile")
        candidate = candidate.split("?")[0]
        candidate = re.sub(r"[^a-zA-Z0-9._-]", "", candidate)
        return candidate[:80] or "profile"
    except Exception:
        return "profile"


async def _fetch_jina_content(profile_url: str) -> str:
    """Fetch readable markdown of a profile page via r.jina.ai. Returns empty string on failure."""
    target = f"{JINA_READER_URL}/{profile_url}"
    headers = {"Accept": "text/plain", "User-Agent": f"{APP_NAME}/1.0"}
    if JINA_API_KEY:
        headers["Authorization"] = f"Bearer {JINA_API_KEY}"
    try:
        async with httpx.AsyncClient(timeout=12) as hc:
            r = await hc.get(target, headers=headers)
            if r.status_code >= 400:
                logger.warning(f"Jina reader returned {r.status_code} for {profile_url[:80]}")
                return ""
            return r.text[:8000]
    except Exception as e:
        logger.warning(f"Jina reader failed for {profile_url[:80]}: {e}")
        return ""


ANALYSIS_SYSTEM = (
    "You are a senior cybersecurity analyst specializing in detecting fake profiles and cyberstalkers "
    "on social media. Given raw public content extracted from a profile page, return ONLY a valid JSON "
    "object (no markdown, no prose outside JSON) with this exact schema:\n"
    "{\n"
    '  "risk_score": <integer 0-100>,\n'
    '  "classification": "Safe" | "Medium Risk" | "High Risk",\n'
    '  "summary": "<2-4 sentence expert analysis ending with one actionable recommendation>",\n'
    '  "red_flags": [{"label": "<short>", "score": <int 5-30>, "description": "<1 sentence>"}],\n'
    '  "toxic_terms": ["<term1>", "<term2>"],\n'
    '  "suspicious_snippets": ["<short excerpt>", ...],\n'
    '  "contact_numbers": ["<phone or WhatsApp number exactly as found>", ...]\n'
    "}\n"
    "Thresholds: <35=Safe, 35-64=Medium Risk, >=65=High Risk. Keep red_flags between 0 and 8. "
    "For contact_numbers, extract any phone, mobile, or WhatsApp numbers visible in the profile's bio, posts, "
    "or captions (preserve country code and formatting). ONLY include numbers that appear VERBATIM in the "
    "provided content. If the page content is unavailable or empty, return an empty array. Never fabricate. "
    "If content is thin or the page failed to load, assume unknown and score around 40 with a red_flag 'Insufficient data'."
)


PHONE_REGEX = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-]?)?\d{3,4}[\s.\-]?\d{3,4}(?:[\s.\-]?\d{2,4})?"
)


def _extract_phone_numbers(text: str) -> List[str]:
    """Heuristic phone-number extraction: keep only plausible numbers with 9-15 digits."""
    if not text:
        return []
    seen = []
    for m in PHONE_REGEX.findall(text or ""):
        digits = re.sub(r"\D", "", m)
        if 9 <= len(digits) <= 15 and m.strip() not in seen:
            seen.append(m.strip())
        if len(seen) >= 10:
            break
    return seen


async def _call_openrouter(profile_url: str, platform: str, content: str) -> dict:
    if not OPENROUTER_API_KEY:
        raise RuntimeError("no_openrouter_key")
    user_prompt = (
        f"Profile URL: {profile_url}\nPlatform: {platform}\n\n"
        f"Public content extracted via Jina Reader (may be partial):\n---\n{content}\n---\n\n"
        "Return the JSON object now."
    )
    body = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": ANALYSIS_SYSTEM},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 900,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": APP_PUBLIC_URL,
        "X-Title": APP_NAME,
    }
    async with httpx.AsyncClient(timeout=60) as hc:
        r = await hc.post("https://openrouter.ai/api/v1/chat/completions", json=body, headers=headers)
        if r.status_code >= 400:
            logger.error(f"OpenRouter error {r.status_code}: {r.text[:300]}")
            raise HTTPException(status_code=502, detail=f"OpenRouter error ({r.status_code})")
        data = r.json()
    try:
        raw = data["choices"][0]["message"]["content"]
        return json.loads(raw)
    except Exception as e:
        logger.error(f"Failed to parse OpenRouter JSON: {e} | raw={str(data)[:400]}")
        raise HTTPException(status_code=502, detail="AI returned invalid JSON")


async def _call_emergent_fallback(profile_url: str, platform: str, content: str) -> dict:
    """Fallback when OpenRouter key is missing — use Emergent LLM key (Claude Sonnet 4.5)."""
    emergent_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not emergent_key:
        raise HTTPException(
            status_code=500,
            detail="No LLM key configured. Set OPENROUTER_API_KEY or EMERGENT_LLM_KEY in backend/.env.",
        )
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except Exception as e:
        logger.error(f"emergentintegrations import failed: {e}")
        raise HTTPException(status_code=500, detail="LLM library unavailable")

    chat = LlmChat(
        api_key=emergent_key,
        session_id=f"detect-{uuid.uuid4()}",
        system_message=ANALYSIS_SYSTEM,
    ).with_model("anthropic", "claude-sonnet-4-5-20250929")

    prompt = (
        f"Profile URL: {profile_url}\nPlatform: {platform}\n\n"
        f"Public content extracted via Jina Reader (may be partial):\n---\n{content}\n---\n\n"
        "Return the JSON object now."
    )
    try:
        resp = await chat.send_message(UserMessage(text=prompt))
    except Exception as e:
        logger.error(f"Emergent LLM error: {e}")
        raise HTTPException(status_code=502, detail="LLM provider error")

    raw = str(resp).strip()
    # Strip code fences if present
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.MULTILINE).strip()
    try:
        return json.loads(raw)
    except Exception as e:
        logger.error(f"Fallback parse failed: {e} | raw={raw[:400]}")
        # Best-effort minimal response
        return {
            "risk_score": 40,
            "classification": "Medium Risk",
            "summary": "AI returned non-JSON output; defaulting to medium-risk pending review.",
            "red_flags": [{"label": "Parser fallback", "score": 10, "description": "LLM JSON parse failed"}],
            "toxic_terms": [],
            "suspicious_snippets": [],
            "contact_numbers": [],
        }


async def _analyze(profile_url: str, platform: str, content: str) -> dict:
    """Try OpenRouter first, fall back to Emergent LLM key if not configured."""
    try:
        return await _call_openrouter(profile_url, platform, content)
    except RuntimeError as e:
        if str(e) == "no_openrouter_key":
            logger.info("OpenRouter key missing — using Emergent LLM fallback")
            return await _call_emergent_fallback(profile_url, platform, content)
        raise


def _classify(score: int) -> str:
    if score >= 65:
        return "High Risk"
    if score >= 35:
        return "Medium Risk"
    return "Safe"


# ---------- Routes ----------
@api_router.get("/")
async def root():
    return {"service": APP_NAME, "status": "online"}


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


@api_router.post("/detect", response_model=ScanResult)
async def detect(data: DetectInput, user: dict = Depends(get_current_user)):
    content = await _fetch_jina_content(data.url)
    if not content:
        username_hint = _extract_username(data.url)
        content = (
            f"[Page content unavailable — Jina Reader could not fetch this URL.]\n"
            f"URL: {data.url}\nPlatform: {data.platform}\nUsername hint: {username_hint}\n"
            "Analyse based on the URL pattern and username only. Note 'Insufficient data' as a red flag."
        )
    ai = await _analyze(data.url, data.platform, content)

    score = int(max(0, min(100, ai.get("risk_score", 40))))
    cls = ai.get("classification") or _classify(score)
    summary = str(ai.get("summary") or "").strip() or "Analysis unavailable."
    red_flags_raw = ai.get("red_flags") or []
    factors: List[RiskFactor] = []
    for f in red_flags_raw[:8]:
        try:
            factors.append(
                RiskFactor(
                    label=str(f.get("label", "Signal"))[:60],
                    score=int(f.get("score", 10)),
                    description=str(f.get("description", ""))[:200],
                )
            )
        except Exception:
            continue
    toxic = [str(t)[:40] for t in (ai.get("toxic_terms") or [])][:10]
    snippets = [str(s)[:120] for s in (ai.get("suspicious_snippets") or [])][:10]

    # Merge AI-returned contact numbers with regex-based extraction (dedupe preserving order)
    ai_numbers = [str(n).strip()[:40] for n in (ai.get("contact_numbers") or []) if str(n).strip()]
    regex_numbers = _extract_phone_numbers(content)
    merged_numbers: List[str] = []
    for n in ai_numbers + regex_numbers:
        if n and n not in merged_numbers:
            merged_numbers.append(n)
    contact_numbers = merged_numbers[:10]

    alert = None
    if cls == "High Risk":
        alert = "High risk — this profile may be fake or a cyberstalker. Block and report."
    elif cls == "Medium Risk":
        alert = "Caution — suspicious patterns detected. Review interactions carefully."

    username = _extract_username(data.url)
    scan = ScanResult(
        id=str(uuid.uuid4()),
        user_id=user["id"],
        username=username,
        platform=data.platform,
        profile_url=data.url,
        risk_score=score,
        classification=cls,
        factors=factors,
        toxic_flags=toxic,
        repeated_messages=snippets,
        contact_numbers=contact_numbers,
        ai_insight=summary,
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
    cursor = db.scans.find(
        {"user_id": user["id"]},
        {"_id": 0, "risk_score": 1, "classification": 1, "created_at": 1},
    ).limit(100)
    items = await cursor.to_list(100)
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
