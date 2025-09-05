#!/usr/bin/env python3
"""
AJ Hacker Chat - WebSocket Chat Server with Admin Panel
Made by AJ APPLICATIONS
"""
import asyncio
import hashlib
import secrets
import time
from typing import Dict, Set, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

# ---------------- Config ----------------
ADMIN_USER = "ajadmin"
# change this password before deploying!
_ADMIN_PASSWORD_PLAINTEXT = "$2y$10$SYqDaSKZu/c3qwlAOT0Iq.u9ysl/9SVI6PlqjmCCxmSLxiWLnLTRa"
ADMIN_PASS_HASH = hashlib.sha256(_ADMIN_PASSWORD_PLAINTEXT.encode()).hexdigest()
ADMIN_TOKEN_TTL = 60 * 60  # 1 hour

# ---------------- App ----------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

clients: Set[Client] = set()
clients_lock = asyncio.Lock()
banned_usernames: Set[str] = set()
admin_tokens: Dict[str, float] = {}

# user mode: anon, hacker, normal
user_modes: Dict[str, str] = {}
# active poll
active_poll: Optional[Dict] = None  # {"question":str,"options":[...],"votes":{username:option}}

# ---------------- Helpers ----------------
def verify_admin_password(password: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASS_HASH

async def broadcast_room(room: str, message: str, exclude: Optional[Client] = None):
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

def create_admin_token() -> str:
    t = secrets.token_urlsafe(24)
    admin_tokens[t] = time.time() + ADMIN_TOKEN_TTL
    return t

async def is_token_valid(token: str) -> bool:
    exp = admin_tokens.get(token)
    if not exp:
        return False
    if exp < time.time():
        admin_tokens.pop(token, None)
        return False
    return True

def format_username(username: str) -> str:
    mode = user_modes.get(username, "normal")
    if mode == "anon":
        return "Anonymous"
    if mode == "hacker":
        return f"{username}💀"
    return username

# ---------------- Web routes ----------------
@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(
        "<h3>AJ Hacker Chat</h3>"
        "<p>WebSocket endpoint: <code>/ws</code></p>"
        "<p>Admin panel: <a href='/admin'>/admin</a></p>"
    )

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    return FileResponse("admin.html", media_type="text/html")
    @app.get("/qazygfxzsergvcakjfhdssdhjgczj,hzbcdsfb,dhczkhz,cgd,cbzhcgzcgd.js", response_class=HTMLResponse)
async def admin_panel():
    return FileResponse("qazygfxzsergvcakjfhdssdhjgczj,hzbcdsfb,dhczkhz,cgd,cbzhcgzcgd.js", media_type="text/javascript")

@app.post("/admin/login")
async def admin_login(payload: Dict):
    if verify_admin_password(payload.get("password","")):
        return {"ok": True, "token": create_admin_token()}
    raise HTTPException(status_code=401, detail="Invalid admin password")

@app.get("/admin/list")
async def admin_list(request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    async with clients_lock:
        return {"ok": True, "users": [
            {"username":c.username,"room":c.room,"connected_at":c.connected_at}
            for c in clients
        ]}

@app.post("/admin/kick")
async def admin_kick(payload: Dict, request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    u = payload.get("username")
    await send_to_user(u, "[SYSTEM] You were kicked by admin.")
    await disconnect_user(u)
    return {"ok": True}

@app.post("/admin/ban")
async def admin_ban(payload: Dict, request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    u = payload.get("username")
    banned_usernames.add(u)
    await send_to_user(u, "[SYSTEM] You were banned by admin.")
    await disconnect_user(u)
    return {"ok": True}

@app.post("/admin/unban")
async def admin_unban(payload: Dict, request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    banned_usernames.discard(payload.get("username"))
    return {"ok": True}

@app.post("/admin/broadcast")
async def admin_broadcast(payload: Dict, request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    msg = payload.get("message","")
    async with clients_lock:
        for c in clients:
            await c.ws.send_text(f"[ADMIN BROADCAST] {msg}")
    return {"ok": True}

@app.post("/admin/poll")
async def admin_poll(payload: Dict, request: Request):
    global active_poll
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    q = payload.get("question")
    opts = payload.get("options", [])
    active_poll = {"question":q, "options":opts, "votes":{}}
    async with clients_lock:
        for c in clients:
            await c.ws.send_text(f"[POLL] {q} Options: {', '.join(opts)}")
    return {"ok": True}

@app.get("/admin/poll/results")
async def poll_results(request: Request):
    token = request.headers.get("authorization","").removeprefix("Bearer ").strip()
    if not await is_token_valid(token):
        raise HTTPException(status_code=401)
    if not active_poll:
        return {"ok": False, "error":"No active poll"}
    counts = {opt:0 for opt in active_poll["options"]}
    for v in active_poll["votes"].values():
        if v in counts: counts[v]+=1
    return {"ok": True,"question":active_poll["question"],"results":counts}

# ---------------- WebSocket chat ----------------
@app.websocket("/ws")
async def ws_handler(ws: WebSocket):
    await ws.accept()
    try:
        await ws.send_text("Enter your username:")
        username = (await ws.receive_text()).strip()
        if not username or username in banned_usernames or username == ADMIN_USER:
            await ws.send_text("Access denied.")
            await ws.close()
            return
        client = Client(ws, username)
        async with clients_lock:
            clients.add(client)
        await broadcast_room("lobby", f"[SYSTEM] {username} joined.")
        while True:
            data = await ws.receive_text()
            if data.startswith("/mode "):
                m = data.split(" ",1)[1].strip().lower()
                if m in ["anon","hacker","normal"]:
                    user_modes[username] = m
                    await ws.send_text(f"[SYSTEM] Mode set to {m}")
                else:
                    await ws.send_text("Modes: anon | hacker | normal")
                continue
            if data.startswith("/img "):
                url = data.split(" ",1)[1].strip()
                await broadcast_room(client.room, f"[{format_username(username)}] [Image] {url}")
                continue
            if data.startswith("/vote "):
                if not active_poll:
                    await ws.send_text("[SYSTEM] No active poll.")
                else:
                    choice = data.split(" ",1)[1].strip()
                    if choice not in active_poll["options"]:
                        await ws.send_text("[SYSTEM] Invalid choice.")
                    else:
                        active_poll["votes"][username] = choice
                        await ws.send_text(f"[SYSTEM] Voted for {choice}")
                continue
            # normal chat
            await broadcast_room(client.room, f"[{format_username(username)}] {data}")
    except WebSocketDisconnect:
        pass
    finally:
        async with clients_lock:
            clients.discard(client)
        await broadcast_room(client.room, f"[SYSTEM] {username} left.")
