#!/usr/bin/env python3
"""
server_secure.py
Secure WebSocket chat server with:
 - ephemeral client session tokens (JWT)
 - admin authentication (bcrypt + JWT)
 - broadcast, poll, image URL, modes, kick, ban
 - rate limiting & origin checking
Run locally:
  export SECRET_KEY="replace_with_strong_random"
  export ADMIN_PASSWORD_HASH="$(python -c "from passlib.context import CryptContext;print(__import__('passlib').context.CryptContext(schemes=['bcrypt']).hash('your_admin_pw'))")"
  uvicorn server_secure:app --host 0.0.0.0 --port 8000
On Render, set SECRET_KEY and ADMIN_PASSWORD_HASH as environment variables in Render dashboard.
"""
import os
import time
import asyncio
import hashlib
import secrets
from typing import Dict, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext

# ---------------- Config (ENV) ----------------
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev_secret_replace_me"  # MUST set in production
JWT_ALG = "HS256"
# admin password hash (bcrypt). Set env ADMIN_PASSWORD_HASH to bcrypt hash of your admin password
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")  # required for production
if not ADMIN_PASSWORD_HASH:
    # for development only: create a default admin pw 'admin123' hashed
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    ADMIN_PASSWORD_HASH = pwd_ctx.hash("admin123")
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# tokens lifetime
CLIENT_TOKEN_EXP = int(os.environ.get("CLIENT_TOKEN_EXP", 300))  # 5 minutes default
ADMIN_TOKEN_EXP = int(os.environ.get("ADMIN_TOKEN_EXP", 3600))   # 1 hour default

# allowed websocket origin(s) (set to your domain in prod)
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")  # use comma-separated list or "*" for dev

# rate limiting
MSG_RATE_LIMIT = int(os.environ.get("MSG_RATE_LIMIT", 5))  # messages
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", 10))      # seconds

# ---------------- App ----------------
app = FastAPI()
# simple CORS for admin panel; tighten in prod to your admin origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ALLOWED_ORIGINS == "*" else [o.strip() for o in ALLOWED_ORIGINS.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- Chat state ----------------
class Client:
    def __init__(self, ws: WebSocket, username: str, room: str = "lobby"):
        self.ws = ws
        self.username = username
        self.room = room
        self.connected_at = time.time()
        self.last_messages: list[float] = []  # timestamps for rate limiting

clients: Set[Client] = set()
clients_lock = asyncio.Lock()
banned_usernames: Set[str] = set()

# admin tokens (JWTs handled statelessly)
# user modes and poll state
user_modes: Dict[str, str] = {}   # username -> mode
active_poll: Optional[Dict] = None  # {"question":..., "options":[..], "votes":{user:opt}}

# ---------------- Helpers ----------------
def create_jwt_token(payload: dict, exp_seconds: int) -> str:
    to_encode = payload.copy()
    to_encode.update({"exp": int(time.time()) + exp_seconds})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALG)

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        return data
    except JWTError:
        return None

def verify_admin_password(plain_password: str) -> bool:
    return pwd_ctx.verify(plain_password, ADMIN_PASSWORD_HASH)

def format_username(username: str) -> str:
    m = user_modes.get(username, "normal")
    if m == "anon": return "Anonymous"
    if m == "hacker": return f"{username}💀"
    return username

async def broadcast_all(message: str):
    async with clients_lock:
        for c in list(clients):
            try:
                await c.ws.send_text(message)
            except:
                pass

async def broadcast_room(room: str, message: str, exclude: Optional[Client]=None):
    async with clients_lock:
        for c in list(clients):
            if c.room == room and c is not exclude:
                try:
                    await c.ws.send_text(message)
                except:
                    pass

async def send_to_user(username: str, message: str):
    async with clients_lock:
        for c in list(clients):
            if c.username == username:
                try:
                    await c.ws.send_text(message)
                except:
                    pass

async def disconnect_user(username: str):
    async with clients_lock:
        for c in list(clients):
            if c.username == username:
                try:
                    await c.ws.close()
                except:
                    pass
                clients.discard(c)

def check_rate_limit(client: Client) -> bool:
    # keep only timestamps inside RATE_WINDOW
    now = time.time()
    client.last_messages = [t for t in client.last_messages if now - t <= RATE_WINDOW]
    if len(client.last_messages) >= MSG_RATE_LIMIT:
        return False
    client.last_messages.append(now)
    return True

def origin_allowed(origin: str) -> bool:
    if ALLOWED_ORIGINS == "*": return True
    allowed = [o.strip() for o in ALLOWED_ORIGINS.split(",")]
    return origin in allowed

# ---------------- Routes ----------------

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse("<h3>AJ Secure Chat</h3><p>Use /ws (WebSocket). Admin panel: /admin</p>")

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return FileResponse("admin.html", media_type="text/html")

@app.post("/session")
async def create_session(payload: Dict):
    """
    Create ephemeral client session token.
    Client posts {"username":"nick"} -> returns {"token": "..."}
    Token short-lived (CLIENT_TOKEN_EXP). Prevents username spoofing.
    """
    username = (payload.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")
    if username in banned_usernames:
        raise HTTPException(status_code=403, detail="banned")
    # prevent reserved admin username
    if username == "ajadmin":
        raise HTTPException(status_code=403, detail="reserved")
    # create token
    token = create_jwt_token({"sub": username, "type":"client"}, CLIENT_TOKEN_EXP)
    return {"token": token, "expires_in": CLIENT_TOKEN_EXP}

@app.post("/admin/login")
async def admin_login(payload: Dict):
    pwd = payload.get("password","")
    if verify_admin_password(pwd):
        token = create_jwt_token({"sub":"ajadmin", "type":"admin"}, ADMIN_TOKEN_EXP)
        return {"ok": True, "token": token}
    raise HTTPException(status_code=401, detail="invalid credentials")

# Admin-protected helpers
def require_admin_token(token: str):
    data = verify_jwt_token(token)
    if not data or data.get("type") != "admin" or data.get("sub") != "ajadmin":
        raise HTTPException(status_code=401, detail="invalid or expired token")

@app.get("/admin/list")
async def admin_list(request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    async with clients_lock:
        users = [{"username":c.username, "room":c.room, "connected_at":c.connected_at} for c in clients]
    return {"ok": True, "users": users}

@app.post("/admin/kick")
async def admin_kick(payload: Dict, request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    u = payload.get("username")
    if not u: raise HTTPException(status_code=400)
    await send_to_user(u, "[SYSTEM] You were kicked by admin.")
    await disconnect_user(u)
    return {"ok": True}

@app.post("/admin/ban")
async def admin_ban(payload: Dict, request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    u = payload.get("username")
    if not u: raise HTTPException(status_code=400)
    banned_usernames.add(u)
    await send_to_user(u, "[SYSTEM] You were banned by admin.")
    await disconnect_user(u)
    return {"ok": True}

@app.post("/admin/unban")
async def admin_unban(payload: Dict, request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    u = payload.get("username")
    banned_usernames.discard(u)
    return {"ok": True}

@app.post("/admin/broadcast")
async def admin_broadcast(payload: Dict, request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    msg = payload.get("message","")
    if not msg: raise HTTPException(status_code=400)
    await broadcast_all(f"[ADMIN BROADCAST] {msg}")
    return {"ok": True}

@app.post("/admin/poll")
async def admin_poll(payload: Dict, request: Request):
    global active_poll
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    q = payload.get("question","")
    opts = payload.get("options",[])
    if not q or not isinstance(opts,list) or not opts:
        raise HTTPException(status_code=400)
    active_poll = {"question": q, "options": opts, "votes": {}}
    await broadcast_all(f"[POLL] {q} Options: {', '.join(opts)}")
    return {"ok": True}

@app.get("/admin/poll/results")
async def admin_poll_results(request: Request):
    auth = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    require_admin_token(auth)
    if not active_poll: return {"ok": False, "error":"no active poll"}
    counts = {opt:0 for opt in active_poll["options"]}
    for v in active_poll["votes"].values():
        if v in counts: counts[v]+=1
    return {"ok": True, "question": active_poll["question"], "results": counts}

# ---------------- WebSocket endpoint ----------------
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # origin check (when available)
    origin = ws.headers.get("origin")
    if origin and not origin_allowed(origin):
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    # accept connection
    await ws.accept()
    # require token param ?token=...
    query = dict(ws._scope.get("query_string", b"").decode().split("&")) if ws._scope.get("query_string") else {}
    token = ws._scope.get("query_string", b"").decode().split("token=")[-1] if ws._scope.get("query_string") else None
    token = token or query.get("token")
    if not token:
        try:
            await ws.send_text("Missing session token. Close.")
            await ws.close()
        except:
            pass
        return
    data = verify_jwt_token(token)
    if not data or data.get("type") != "client":
        try:
            await ws.send_text("Invalid/expired token. Close.")
            await ws.close()
        except:
            pass
        return
    username = data.get("sub")
    # final ban/validation
    if not username or username in banned_usernames:
        await ws.send_text("Access denied.")
        await ws.close()
        return
    # create client and add
    client = Client(ws=ws, username=username, room="lobby")
    async with clients_lock:
        clients.add(client)
    await broadcast_room("lobby", f"[SYSTEM] {username} joined.")
    try:
        while True:
            text = await ws.receive_text()
            text = (text or "").strip()
            if not text: continue
            # rate limit
            if not check_rate_limit(client):
                await ws.send_text("[SYSTEM] Rate limit exceeded. Slow down.")
                continue
            # commands
            if text.startswith("/mode "):
                m = text.split(" ",1)[1].strip().lower()
                if m in ("anon","hacker","normal"):
                    user_modes[username] = m
                    await ws.send_text(f"[SYSTEM] Mode set to {m}")
                else:
                    await ws.send_text("[SYSTEM] Modes: anon|hacker|normal")
                continue
            if text.startswith("/img "):
                url = text.split(" ",1)[1].strip()
                await broadcast_room(client.room, f"[{format_username(username)}] [Image] {url}")
                continue
            if text.startswith("/msg "):
                # /msg target message
                parts = text.split(" ",2)
                if len(parts) >=3:
                    target, msg = parts[1], parts[2]
                    await send_to_user(target, f"[PM] {format_username(username)}: {msg}")
                continue
            if text.startswith("/join "):
                new_room = text.split(" ",1)[1].strip() or "lobby"
                old = client.room
                client.room = new_room
                await broadcast_room(old, f"[SYSTEM] {username} left to {new_room}")
                await broadcast_room(new_room, f"[SYSTEM] {username} joined {new_room}")
                continue
            if text.startswith("/vote "):
                if not active_poll:
                    await ws.send_text("[SYSTEM] No active poll.")
                    continue
                choice = text.split(" ",1)[1].strip()
                if choice not in active_poll["options"]:
                    await ws.send_text("[SYSTEM] Invalid option.")
                    continue
                active_poll["votes"][username] = choice
                await ws.send_text(f"[SYSTEM] Voted: {choice}")
                continue
            # default broadcast to room
            await broadcast_room(client.room, f"[{format_username(username)}] {text}")
    except WebSocketDisconnect:
        pass
    finally:
        async with clients_lock:
            clients.discard(client)
        await broadcast_room(client.room, f"[SYSTEM] {username} left.")
