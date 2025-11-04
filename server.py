# server.py
import os, secrets, mimetypes, base64
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (Column, String, Integer, LargeBinary, DateTime, Boolean,
                        create_engine, ForeignKey, select)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from auth.login import make_login_hash, verify_login_hash
import jwt

from dotenv import load_dotenv
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET","dev-secret-change-me")

if JWT_SECRET == "dev-secret-change-me":
    print("!!! WARNING: SERVER IS USING THE DEFAULT DEV SECRET !!!")
else:
    print("Server is using your custom secret.")
    
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

class Group(Base):
    __tablename__ = "groups"
    id = Column(String(12), primary_key=True)
    name = Column(String(100), nullable=False)
    creator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=_now)
    # Store the encrypted group key for the creator
    # This will be replicated in GroupMembership for each member
    creator = relationship("User", foreign_keys=[creator_id])
    members = relationship("GroupMembership", back_populates="group", cascade="all, delete-orphan")
    messages = relationship("GroupMessage", back_populates="group", cascade="all, delete-orphan")

class GroupMembership(Base):
    __tablename__ = "group_memberships"
    id = Column(Integer, primary_key=True)
    group_id = Column(String(12), ForeignKey("groups.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Encrypted group key specific to this user (encrypted with their passphrase)
    encrypted_group_key_b64 = Column(String, nullable=False)
    joined_at = Column(DateTime, default=_now)
    is_admin = Column(Boolean, default=False, nullable=False)
    
    group = relationship("Group", back_populates="members")
    user = relationship("User")

class GroupMessage(Base):
    __tablename__ = "group_messages"
    id = Column(String(12), primary_key=True)
    group_id = Column(String(12), ForeignKey("groups.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Encrypted message blob (encrypted with the group key)
    encrypted_blob = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=_now)
    
    group = relationship("Group", back_populates="messages")
    sender = relationship("User")

Base.metadata.create_all(engine)

app = FastAPI(title="CipherDrop", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# Mount static files
app.mount("/assets", StaticFiles(directory="assets"), name="assets")

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

# --- Schemas: Groups ---
class CreateGroupReq(BaseModel):
    name: str = Field(..., description="Group name")
    encrypted_group_key_b64: str = Field(..., description="Base64 encoded encrypted group key for creator")

class AddMemberReq(BaseModel):
    username: str = Field(..., description="Username to add")
    encrypted_group_key_b64: str = Field(..., description="Encrypted group key for this user")

class SendGroupMessageReq(BaseModel):
    encrypted_blob_b64: str = Field(..., description="Base64 encoded encrypted message")

class GroupInfo(BaseModel):
    id: str
    name: str
    creator: str
    created_at: str
    is_admin: bool
    encrypted_group_key_b64: str

class GroupMemberInfo(BaseModel):
    username: str
    joined_at: str
    is_admin: bool

class GroupMessageInfo(BaseModel):
    id: str
    sender: str
    encrypted_blob_b64: str
    created_at: str

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

# --- Routes: Groups ---
@app.post("/api/groups/create", response_model=dict)
def create_group(body: CreateGroupReq, me: User = Depends(bearer(None))):
    """Create a new group. The creator must provide their encrypted group key."""
    with SessionLocal() as db:
        group_id = _gen_id()
        
        # Create the group
        new_group = Group(
            id=group_id,
            name=body.name,
            creator_id=me.id,
            created_at=_now()
        )
        db.add(new_group)
        
        # Add creator as admin member
        membership = GroupMembership(
            group_id=group_id,
            user_id=me.id,
            encrypted_group_key_b64=body.encrypted_group_key_b64,
            is_admin=True,
            joined_at=_now()
        )
        db.add(membership)
        db.commit()
        
        return {"id": group_id, "name": body.name}

@app.get("/api/groups", response_model=list[GroupInfo])
def list_groups(me: User = Depends(bearer(None))):
    """List all groups the user is a member of."""
    with SessionLocal() as db:
        memberships = db.execute(
            select(GroupMembership).where(GroupMembership.user_id == me.id)
        ).scalars().all()
        
        result = []
        for membership in memberships:
            group = db.get(Group, membership.group_id)
            if group:
                creator = db.get(User, group.creator_id)
                result.append(GroupInfo(
                    id=group.id,
                    name=group.name,
                    creator=creator.username,
                    created_at=group.created_at.isoformat(),
                    is_admin=membership.is_admin,
                    encrypted_group_key_b64=membership.encrypted_group_key_b64
                ))
        
        return result

@app.get("/api/groups/{group_id}/members", response_model=list[GroupMemberInfo])
def list_group_members(group_id: str, me: User = Depends(bearer(None))):
    """List all members of a group."""
    with SessionLocal() as db:
        # Check if user is a member
        my_membership = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == me.id
            )
        ).scalar_one_or_none()
        
        if not my_membership:
            raise HTTPException(403, "You are not a member of this group")
        
        # Get all members
        memberships = db.execute(
            select(GroupMembership).where(GroupMembership.group_id == group_id)
        ).scalars().all()
        
        result = []
        for membership in memberships:
            user = db.get(User, membership.user_id)
            if user:
                result.append(GroupMemberInfo(
                    username=user.username,
                    joined_at=membership.joined_at.isoformat(),
                    is_admin=membership.is_admin
                ))
        
        return result

@app.post("/api/groups/{group_id}/members", response_model=dict)
def add_group_member(group_id: str, body: AddMemberReq, me: User = Depends(bearer(None))):
    """Add a member to a group. Only admins can add members."""
    with SessionLocal() as db:
        # Check if requester is an admin
        my_membership = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == me.id
            )
        ).scalar_one_or_none()
        
        if not my_membership or not my_membership.is_admin:
            raise HTTPException(403, "Only admins can add members")
        
        # Find user to add
        user_to_add = db.query(User).filter_by(username=body.username).first()
        if not user_to_add:
            raise HTTPException(404, "User not found")
        
        # Check if already a member
        existing = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == user_to_add.id
            )
        ).scalar_one_or_none()
        
        if existing:
            raise HTTPException(409, "User is already a member")
        
        # Add membership
        membership = GroupMembership(
            group_id=group_id,
            user_id=user_to_add.id,
            encrypted_group_key_b64=body.encrypted_group_key_b64,
            is_admin=False,
            joined_at=_now()
        )
        db.add(membership)
        db.commit()
        
        return {"ok": True, "username": body.username}

@app.delete("/api/groups/{group_id}/members/{username}", response_model=dict)
def remove_group_member(group_id: str, username: str, me: User = Depends(bearer(None))):
    """Remove a member from a group. Admins can remove anyone, users can remove themselves."""
    with SessionLocal() as db:
        # Check if requester is a member
        my_membership = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == me.id
            )
        ).scalar_one_or_none()
        
        if not my_membership:
            raise HTTPException(403, "You are not a member of this group")
        
        # Find user to remove
        user_to_remove = db.query(User).filter_by(username=username).first()
        if not user_to_remove:
            raise HTTPException(404, "User not found")
        
        # Check permissions
        if user_to_remove.id != me.id and not my_membership.is_admin:
            raise HTTPException(403, "Only admins can remove other members")
        
        # Find and remove membership
        membership_to_remove = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == user_to_remove.id
            )
        ).scalar_one_or_none()
        
        if not membership_to_remove:
            raise HTTPException(404, "User is not a member")
        
        db.delete(membership_to_remove)
        db.commit()
        
        return {"ok": True}

@app.post("/api/groups/{group_id}/messages", response_model=dict)
def send_group_message(group_id: str, body: SendGroupMessageReq, me: User = Depends(bearer(None))):
    """Send a message to a group. Message should be encrypted with the group key."""
    with SessionLocal() as db:
        # Check if user is a member
        membership = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == me.id
            )
        ).scalar_one_or_none()
        
        if not membership:
            raise HTTPException(403, "You are not a member of this group")
        
        # Decode and store the message
        import base64
        encrypted_blob = base64.b64decode(body.encrypted_blob_b64)
        
        msg_id = _gen_id()
        message = GroupMessage(
            id=msg_id,
            group_id=group_id,
            sender_id=me.id,
            encrypted_blob=encrypted_blob,
            created_at=_now()
        )
        db.add(message)
        db.commit()
        
        return {"id": msg_id, "created_at": message.created_at.isoformat()}

@app.get("/api/groups/{group_id}/messages", response_model=list[GroupMessageInfo])
def get_group_messages(group_id: str, limit: int = 50, me: User = Depends(bearer(None))):
    """Get messages from a group. Returns encrypted messages."""
    with SessionLocal() as db:
        # Check if user is a member
        membership = db.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_id,
                GroupMembership.user_id == me.id
            )
        ).scalar_one_or_none()
        
        if not membership:
            raise HTTPException(403, "You are not a member of this group")
        
        # Get messages (most recent first)
        messages = db.execute(
            select(GroupMessage)
            .where(GroupMessage.group_id == group_id)
            .order_by(GroupMessage.created_at.desc())
            .limit(limit)
        ).scalars().all()
        
        result = []
        for msg in reversed(messages):  # Reverse to show oldest first
            sender = db.get(User, msg.sender_id)
            import base64
            result.append(GroupMessageInfo(
                id=msg.id,
                sender=sender.username if sender else "Unknown",
                encrypted_blob_b64=base64.b64encode(msg.encrypted_blob).decode(),
                created_at=msg.created_at.isoformat()
            ))
        
        return result

@app.delete("/api/groups/{group_id}", response_model=dict)
def delete_group(group_id: str, me: User = Depends(bearer(None))):
    """Delete a group. Only the creator can delete a group."""
    with SessionLocal() as db:
        group = db.get(Group, group_id)
        if not group:
            raise HTTPException(404, "Group not found")
        
        if group.creator_id != me.id:
            raise HTTPException(403, "Only the creator can delete the group")
        
        db.delete(group)
        db.commit()
        
        return {"ok": True}

# --- Routes: welcome page ---
@app.get("/", response_class=HTMLResponse)
def welcome():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to CipherDrop</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #fff;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                text-align: center;
            }
            .container {
                max-width: 800px;
                padding: 40px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            h1 {
                font-size: 3rem;
                margin-bottom: 20px;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
            }
            p {
                font-size: 1.2rem;
                margin-bottom: 30px;
                line-height: 1.6;
            }
            .image-container {
                margin: 30px 0;
            }
            img {
                max-width: 100%;
                height: auto;
                border-radius: 15px;
                box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            }
            .cta-button {
                display: inline-block;
                padding: 15px 30px;
                background: linear-gradient(45deg, #ff6b6b, #ffa500);
                color: white;
                text-decoration: none;
                border-radius: 50px;
                font-weight: bold;
                font-size: 1.1rem;
                transition: all 0.3s ease;
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            }
            .cta-button:hover {
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
            }
            .features {
                margin-top: 40px;
                display: flex;
                justify-content: space-around;
                flex-wrap: wrap;
            }
            .feature {
                flex: 1;
                min-width: 200px;
                margin: 10px;
                padding: 20px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                backdrop-filter: blur(5px);
            }
            .feature h3 {
                margin-top: 0;
                color: #ffd700;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to CipherDrop</h1>
            <p>ardi makan sayur atau aril tahu penghuni kos dengan asbun, mana yang lebih tidak mungkin</p>
            
            <div class="image-container">
                <img src="/assets/ardi.png" alt="CipherDrop Logo" />
            </div>
            
            <a href="/docs" class="cta-button">Explore API Documentation</a>
            
            
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
