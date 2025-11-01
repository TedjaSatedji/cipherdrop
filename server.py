# server.py
import os, secrets, mimetypes, base64
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (Column, String, Integer, LargeBinary, DateTime, Boolean,
                        create_engine, ForeignKey, select)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from auth.login import make_login_hash, verify_login_hash
import jwt

JWT_SECRET = os.getenv("JWT_SECRET","dev-secret-change-me")
JWT_ISS = "cipherdrop"
DB_URL = "sqlite:///./dropbox.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def _now():
    # naive UTC to match what SQLite returns
    return datetime.utcnow() + timedelta(hours=7)
def _gen_id(n=8): return secrets.token_urlsafe(n)[:12]
def _ttl_minutes(default=30):
    try: return int(os.getenv("TTL_MIN", default))
    except: return default

class User(Base):
    __tablename__="users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    pw_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=_now)

class Item(Base):
    __tablename__ = "items"
    id = Column(String(12), primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255))
    mime = Column(String(80), nullable=False)
    blob = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    consumed = Column(Boolean, default=False, nullable=False)
    one_time = Column(Boolean, default=True, nullable=False)
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

Base.metadata.create_all(engine)

app = FastAPI(title="CipherDrop", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# --- Auth helpers ---
# after
def _already_downloaded(rec: Item) -> bool:
    return bool(rec.one_time and rec.consumed)

import time
def issue_token(user: User) -> str:
    now = int(time.time())
    payload = {
        "sub": user.username, "uid": user.id, "iss": JWT_ISS,
        "iat": now, "exp": now + 8*3600
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_user_from_token(token: str) -> User:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer=JWT_ISS)
    except Exception:
        raise HTTPException(401, "invalid token")
    with SessionLocal() as db:
        u = db.get(User, data["uid"])
        if not u: raise HTTPException(401, "user not found")
        return u

def bearer(token: Optional[str]=None):
    # Accept "Authorization: Bearer <token>" via dependency
    from fastapi import Header
    def dep(authorization: Optional[str]=Header(None)):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "missing bearer")
        tok = authorization.split(" ",1)[1]
        return get_user_from_token(tok)
    return dep

# --- Schemas ---
class RegisterReq(BaseModel):
    username: str
    password: str

class LoginReq(BaseModel):
    username: str
    password: str

class SendJSON(BaseModel):
    to: str = Field(..., description="receiver username")
    payload_b64: str
    filename: Optional[str]=None
    mime: Optional[str]="application/octet-stream"
    ttl_min: Optional[int]=None
    one_time: Optional[bool]=True

class SendResp(BaseModel):
    id: str
    expires_at: str
    to: str

class InboxItem(BaseModel):
    id: str
    from_user: str
    filename: Optional[str]
    mime: str
    created_at: str
    expires_at: str
    consumed: bool

# --- Routes: auth ---
@app.post("/auth/register")
def register(body: RegisterReq):
    with SessionLocal() as db:
        if db.query(User).filter_by(username=body.username).first():
            raise HTTPException(409, "username exists")
        db.add(User(username=body.username, pw_hash=make_login_hash(body.password)))
        db.commit()
    return {"ok": True}

@app.post("/auth/login")
def login(body: LoginReq):
    with SessionLocal() as db:
        u = db.query(User).filter_by(username=body.username).first()
        if not u: raise HTTPException(401, "bad credentials")
        try:
            verify_login_hash(body.password, u.pw_hash)
        except Exception:
            raise HTTPException(401, "bad credentials")
        return {"token": issue_token(u)}

# --- Routes: send ---
@app.post("/api/send-json", response_model=SendResp)
def send_json(body: SendJSON, me: User = Depends(bearer(None))):
    import base64
    data = base64.b64decode(body.payload_b64)
    with SessionLocal() as db:
        receiver = db.query(User).filter_by(username=body.to).first()
        if not receiver: raise HTTPException(404, "recipient not found")
        item_id = _gen_id()
        ttl = body.ttl_min or _ttl_minutes()
        db.add(Item(
            id=item_id, sender_id=me.id, receiver_id=receiver.id, one_time=bool(body.one_time), 
            filename=body.filename, mime=body.mime or "application/octet-stream",
            blob=data, created_at=_now(), expires_at=_now()+timedelta(minutes=ttl),
            consumed=False
        ))
        db.commit()
        return SendResp(id=item_id, expires_at=(_now()+timedelta(minutes=ttl)).isoformat(), to=receiver.username)

@app.post("/api/send-file", response_model=SendResp)
def send_file(to: str = Form(...),
              ttl_min: Optional[int]=Form(None),
              one_time: Optional[bool] = Form(True),
              file: UploadFile = File(...),
              me: User = Depends(bearer(None))):
    data = file.file.read()
    with SessionLocal() as db:
        receiver = db.query(User).filter_by(username=to).first()
        if not receiver: raise HTTPException(404, "recipient not found")
        item_id = _gen_id()
        ttl = ttl_min or _ttl_minutes()
        mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
        db.add(Item(
            id=item_id, sender_id=me.id, receiver_id=receiver.id, one_time=bool(one_time),
            filename=file.filename, mime=mime, blob=data,
            created_at=_now(), expires_at=_now()+timedelta(minutes=ttl), consumed=False
        ))
        db.commit()
        return SendResp(id=item_id, expires_at=(_now()+timedelta(minutes=ttl)).isoformat(), to=receiver.username)

# --- Routes: inbox/recv/delete ---
@app.get("/api/inbox", response_model=list[InboxItem])
def inbox(me: User = Depends(bearer(None))):
    with SessionLocal() as db:
        rows = db.execute(select(Item).where(Item.receiver_id==me.id)).scalars().all()
        return [InboxItem(
            id=r.id, from_user=db.get(User, r.sender_id).username,
            filename=r.filename, mime=r.mime,
            created_at=r.created_at.isoformat(), expires_at=r.expires_at.isoformat(),
            consumed=r.consumed
        ) for r in rows]


@app.get("/api/recv/{item_id}")
def recv(item_id: str, me: User = Depends(bearer(None))):
    with SessionLocal() as db:
        rec = db.get(Item, item_id)
        if not rec: raise HTTPException(404, "not found")
        if rec.receiver_id != me.id: raise HTTPException(403, "not yours")
        if rec.expires_at < _now(): raise HTTPException(410, "expired")
        if _already_downloaded(rec): raise HTTPException(410, "already downloaded")

        data = bytes(rec.blob)
        mime = rec.mime or "application/octet-stream"
        filename = rec.filename

        if rec.one_time:                    # consume only if one-time
            rec.consumed = True
            db.add(rec); db.commit()

    headers = {}
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return Response(content=data, media_type=mime, headers=headers)

@app.get("/api/recv64/{item_id}")
def recv64(item_id: str, me: User = Depends(bearer(None))):
    import base64
    with SessionLocal() as db:
        rec = db.get(Item, item_id)
        if not rec: raise HTTPException(404, "not found")
        if rec.receiver_id != me.id: raise HTTPException(403, "not yours")
        if rec.expires_at < _now(): raise HTTPException(410, "expired")
        if _already_downloaded(rec): raise HTTPException(410, "already downloaded")

        data = bytes(rec.blob)
        mime = rec.mime or "application/octet-stream"
        filename = rec.filename

        if rec.one_time:
            rec.consumed = True
            db.add(rec); db.commit()

    return {"id": item_id, "mime": mime, "filename": filename,
            "b64": base64.b64encode(data).decode()}
    
@app.delete("/api/recv/{item_id}")
def delete_item(item_id: str, me: User = Depends(bearer(None))):
    with SessionLocal() as db:
        rec = db.get(Item, item_id)
        if not rec: raise HTTPException(404, "not found")
        if rec.sender_id != me.id and rec.receiver_id != me.id:
            raise HTTPException(403, "not yours")
        db.delete(rec); db.commit()
    return {"ok": True}

@app.post("/admin/cleanup")
def cleanup():
    with SessionLocal() as db:
        cnt=0
        for rec in db.execute(select(Item)).scalars().all():
            if rec.expires_at < _now() or rec.consumed:
                db.delete(rec); cnt+=1
        db.commit()
    return {"deleted": cnt}
