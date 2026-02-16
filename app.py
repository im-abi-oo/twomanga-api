# Two Manga API — Professional Queue Mode (Fully Fixed & Robust)
# Fixes: Bad Request Handler, Infinite Coupon Glitch, Thread Safety

import os
import uuid
import json
import logging
import datetime
import time
import threading
import queue
import atexit
from functools import wraps
from concurrent.futures import Future
from typing import Optional, Any, Callable, Dict

from flask import Flask, request, jsonify, g
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates, EXCLUDE
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from bson.objectid import ObjectId
from bson.errors import InvalidId
import bcrypt

# ----- CONFIG & LOGGING -----
class AppConfig:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    MONGO_DBNAME = os.getenv("MONGO_DBNAME", "twomanga")
    APP_PORT = int(os.getenv("PORT", "5001"))
    WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
    JOB_WAIT_SECONDS = float(os.getenv("JOB_WAIT_SECONDS", "8.0"))
    
    ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]
    ADMIN_ENV_USER = os.getenv("ADMIN_USERNAME")
    ADMIN_ENV_PASS = os.getenv("ADMIN_PASSWORD")
    BCRYPT_ROUNDS = 12

# Simple fallback for local testing if env vars missing
if not AppConfig.MONGO_URI:
    print("WARNING: MONGO_URI missing. Set it in environment variables.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("TwoMangaCore")

# ----- UTILITIES -----
def get_utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=AppConfig.BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False

# ----- DATABASE MANAGER -----
class MongoManager:
    def __init__(self, uri: str, db_name: str):
        self._uri = uri
        self._db_name = db_name
        self._client: Optional[MongoClient] = None
        self._db = None
        self._connect_lock = threading.Lock()

    def get_db(self):
        if self._db is not None:
            return self._db
        with self._connect_lock:
            if self._db is not None: return self._db
            try:
                self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000)
                self._client.admin.command('ping')
                try:
                    target_db = MongoClient(self._uri).get_default_database().name
                except:
                    target_db = self._db_name
                self._db = self._client[target_db]
                logger.info(f"DB Connected: {target_db}")
                return self._db
            except Exception as e:
                logger.critical(f"DB Connection failed: {e}")
                raise ConnectionFailure("Database unavailable")

    def is_alive(self) -> bool:
        try:
            if self._client:
                self._client.admin.command('ping')
                return True
            return False
        except:
            return False
            
    def get_collection(self, name: str):
        return self.get_db()[name]

db_core = MongoManager(AppConfig.MONGO_URI, AppConfig.MONGO_DBNAME)

# ----- WORKER ENGINE -----
class JobWrapper:
    def __init__(self, priority: int, func: Callable, args: tuple, kwargs: dict):
        self.priority = priority
        self.sequence = time.time_ns()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.future = Future()

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.sequence < other.sequence

class WorkerEngine:
    def __init__(self, num_workers: int):
        self.queue = queue.PriorityQueue()
        self.threads = []
        self._shutdown = threading.Event()
        self.num_workers = num_workers

    def start(self):
        logger.info(f"Starting {self.num_workers} Workers...")
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"Worker-{i}", daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self._shutdown.set()
        for _ in self.threads:
            self.queue.put(JobWrapper(-1, lambda: None, (), {})) 

    def _worker_loop(self):
        while not self._shutdown.is_set():
            try:
                job: JobWrapper = self.queue.get(timeout=2.0)
                if job.priority == -1: 
                    self.queue.task_done(); continue
                try:
                    result = job.func(*job.args, **job.kwargs)
                    if not job.future.done(): job.future.set_result(result)
                except Exception as e:
                    logger.error(f"Job Error: {e}")
                    if not job.future.done(): job.future.set_exception(e)
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue

    def submit_job(self, func, *args, priority=10, wait=False, **kwargs) -> Dict[str, Any]:
        job = JobWrapper(priority, func, args, kwargs)
        self.queue.put(job)
        if not wait:
            return {"queued": True, "job_id": job.sequence}
        try:
            result = job.future.result(timeout=AppConfig.JOB_WAIT_SECONDS)
            return {"finished": True, "result": result}
        except TimeoutError:
            return {"finished": False, "msg": "Server busy"}
        except Exception as e:
            return {"finished": True, "error_msg": str(e)}

worker_engine = WorkerEngine(AppConfig.WORKER_COUNT)

# ----- FLASK APP -----
app = Flask(__name__)
app.config["MONGO_URI"] = AppConfig.MONGO_URI
app.config["JWT_SECRET_KEY"] = AppConfig.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=6)
jwt = JWTManager(app)
CORS(app, supports_credentials=True)

# ----- SCHEMAS -----
class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    @validates("username")
    def validate_username(self, val, **kwargs):
        if len(val.strip()) < 3: raise ValidationError("Username too short")

class PaymentSchema(Schema):
    days = fields.Int(required=False, allow_none=True)
    tx_hash = fields.Str(load_default=None)
    coupon_code = fields.Str(load_default=None)
    @validates("days")
    def validate_days(self, value, **kwargs):
        if value and (value < 1 or value > 3650): raise ValidationError("Invalid days")

class CouponSchema(Schema):
    code = fields.Str(required=True)
    bonus_days = fields.Int(required=True)
    max_uses = fields.Int(load_default=None, allow_none=True)
    expires_at = fields.DateTime(load_default=None, allow_none=True)

# ----- MIDDLEWARE -----
def strict_session(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        ident = get_jwt_identity()
        user = db_core.get_collection("users").find_one({"username": ident.lower()})
        if not user or user.get("session_salt") != claims.get("session_salt"):
            return jsonify({"msg": "Session invalid"}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        ident = get_jwt_identity()
        is_admin = ident in AppConfig.ADMIN_USERNAMES or (AppConfig.ADMIN_ENV_USER and ident == AppConfig.ADMIN_ENV_USER.lower())
        if not is_admin:
            user = db_core.get_collection("users").find_one({"username": ident})
            if user and user.get("role") == "admin": is_admin = True
        
        if is_admin:
            g.current_user = {"username": ident, "role": "admin"}
            return fn(*args, **kwargs)
        return jsonify({"msg": "Admin only"}), 403
    return wrapper

# ----- WORKER LOGIC (FIXED) -----

def worker_logic_payment(user_id_str, data):
    """
    Fixed Logic: Checks used_by list to prevent coupon reuse.
    """
    db = db_core.get_db()
    user_oid = ObjectId(user_id_str)
    user = db.users.find_one({"_id": user_oid})
    if not user: return {"msg": "User not found"}, 404

    coupon_code = data.get("coupon_code")
    
    # 1. Coupon Flow
    if coupon_code:
        c_doc = db.coupons.find_one({"code": coupon_code})
        if not c_doc:
            return {"msg": "Invalid coupon code"}, 400
        
        # Check Expiry
        if c_doc.get("expires_at") and c_doc["expires_at"].replace(tzinfo=datetime.timezone.utc) < get_utc_now():
            db.coupons.delete_one({"_id": c_doc["_id"]})
            return {"msg": "Coupon expired"}, 400

        # Check Global Limit
        max_uses = c_doc.get("max_uses")
        if max_uses is not None and c_doc.get("uses", 0) >= max_uses:
            db.coupons.delete_one({"_id": c_doc["_id"]})
            return {"msg": "Coupon usage limit reached"}, 400

        # [CRITICAL FIX] Check per-user limit
        used_by = c_doc.get("used_by", [])
        if user_oid in used_by:
            return {"msg": "You have already used this coupon"}, 400

        # Apply Bonus
        bonus = c_doc.get("bonus_days", 0)
        curr_expiry = user.get("expiryDate")
        now = get_utc_now()
        
        if curr_expiry:
            if curr_expiry.tzinfo is None: curr_expiry = curr_expiry.replace(tzinfo=datetime.timezone.utc)
            start_point = max(curr_expiry, now)
        else:
            start_point = now

        new_expiry = start_point + datetime.timedelta(days=bonus)
        
        # DB Updates
        db.users.update_one({"_id": user_oid}, {
            "$set": {"expiryDate": new_expiry},
            "$inc": {"total_purchases": 1}
        })
        
        # Atomic Update for Coupon
        db.coupons.update_one(
            {"_id": c_doc["_id"]}, 
            {
                "$inc": {"uses": 1},
                "$push": {"used_by": user_oid}
            }
        )
        
        # Cleanup if full
        if max_uses is not None and (c_doc.get("uses", 0) + 1) >= max_uses:
            db.coupons.delete_one({"_id": c_doc["_id"]})

        return {"msg": "Coupon applied", "new_expiry": new_expiry.isoformat()}, 200

    # 2. Transaction Flow
    tx_hash = data.get("tx_hash")
    if not tx_hash: return {"msg": "TX Hash required"}, 400
    
    if db.transactions.find_one({"tx_hash": tx_hash}):
        return {"msg": "Transaction already exists"}, 409

    doc = {
        "user_id": user_oid,
        "username": user["username"],
        "tx_hash": tx_hash,
        "days": data.get("days", 30),
        "status": "pending",
        "created_at": get_utc_now()
    }
    new_tx = db.transactions.insert_one(doc)
    return {"msg": "Transaction pending", "tx_id": str(new_tx.inserted_id)}, 201

def worker_logic_approve(tx_id, admin_user):
    db = db_core.get_db()
    try: oid = ObjectId(tx_id)
    except: return {"msg": "Bad ID"}, 400
    
    tx = db.transactions.find_one({"_id": oid, "status": "pending"})
    if not tx: return {"msg": "TX not found/pending"}, 404
    
    user = db.users.find_one({"_id": tx["user_id"]})
    if not user: return {"msg": "User missing"}, 404
    
    now = get_utc_now()
    cur = user.get("expiryDate")
    if cur and cur.tzinfo is None: cur = cur.replace(tzinfo=datetime.timezone.utc)
    
    start = max(cur, now) if cur else now
    new_exp = start + datetime.timedelta(days=tx.get("days", 0))
    
    db.users.update_one({"_id": user["_id"]}, {
        "$set": {"expiryDate": new_exp},
        "$inc": {"total_purchases": 1}
    })
    db.transactions.update_one({"_id": oid}, {
        "$set": {"status": "approved", "approved_by": admin_user, "processed_at": now}
    })
    return {"msg": "Approved", "new_expiry": new_exp.isoformat()}, 200

# ----- ROUTES (FIXED Bad Request) -----

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "Online", "workers": worker_engine.num_workers})

@app.route("/auth/register", methods=["POST"])
def register():
    # FIX: Use get_json(silent=True) to avoid 400 crash
    json_data = request.get_json(silent=True)
    if not json_data: return jsonify({"msg": "JSON required"}), 400
    
    try: data = RegisterSchema().load(json_data)
    except ValidationError as e: return jsonify(e.messages), 400
    
    db = db_core.get_db()
    username = data["username"].strip().lower()
    
    if db.users.find_one({"username": username}):
        return jsonify({"msg": "Taken"}), 409
        
    doc = {
        "username": username,
        "password": hash_password(data["password"]),
        "role": "user",
        "session_salt": str(uuid.uuid4()),
        "created_at": get_utc_now()
    }
    db.users.insert_one(doc)
    return jsonify({"msg": "Created"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    json_data = request.get_json(silent=True)
    if not json_data: return jsonify({"msg": "JSON required"}), 400
    
    username = json_data.get("username", "").lower()
    password = json_data.get("password", "")
    
    user = db_core.get_collection("users").find_one({"username": username})
    if not user or not check_password(password, user["password"]):
        return jsonify({"msg": "Invalid login"}), 401
        
    salt = str(uuid.uuid4())
    db_core.get_collection("users").update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
    
    access = create_access_token(identity=username, additional_claims={"session_salt": salt})
    return jsonify({"access_token": access})

@app.route("/auth/me", methods=["GET"])
@strict_session
def me():
    def _fetch(u_name):
        u = db_core.get_collection("users").find_one({"username": u_name})
        exp = u.get("expiryDate")
        if exp and exp.tzinfo is None: exp = exp.replace(tzinfo=datetime.timezone.utc)
        days = (exp - get_utc_now()).days if exp and exp > get_utc_now() else 0
        return {"username": u["username"], "days_left": days, "expiry": exp.isoformat() if exp else None}
    
    job = worker_engine.submit_job(_fetch, g.current_user["username"], wait=True)
    return jsonify(job["result"]) if job.get("finished") else (jsonify({"msg":"Busy"}), 202)

@app.route("/payment/submit", methods=["POST"])
@strict_session
def payment_submit():
    # FIX: Robust JSON parsing
    json_data = request.get_json(silent=True)
    if not json_data:
        return jsonify({"msg": "Missing JSON body or Content-Type header"}), 400

    try:
        data = PaymentSchema().load(json_data, unknown=EXCLUDE)
    except ValidationError as e:
        return jsonify(e.messages), 400

    if not data.get("coupon_code") and not data.get("days"):
        return jsonify({"msg": "days required if no coupon"}), 400

    job = worker_engine.submit_job(
        worker_logic_payment,
        str(g.current_user["_id"]),
        data,
        priority=10,
        wait=True
    )
    
    if job.get("finished"):
        if job.get("error_msg"): return jsonify({"msg": "System Error"}), 500
        res, code = job["result"]
        return jsonify(res), code
        
    return jsonify({"msg": "Queued"}), 202

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_txs():
    cursor = db_core.get_collection("transactions").find().sort("created_at", -1).limit(50)
    return jsonify([{**t, "_id": str(t["_id"]), "user_id": str(t["user_id"])} for t in cursor])

@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@admin_required
def admin_approve(tx_id):
    job = worker_engine.submit_job(worker_logic_approve, tx_id, g.current_user["username"], wait=True)
    if job.get("finished"):
        res, code = job["result"]
        return jsonify(res), code
    return jsonify({"msg": "Queued"}), 202

@app.route("/admin/transactions/<tx_id>/reject", methods=["POST"])
@admin_required
def admin_reject(tx_id):
    # Fix: Safer JSON get
    body = request.get_json(silent=True) or {}
    reason = body.get("reason", "No reason")
    
    def _reject(tid, admin, rsn):
        try: oid = ObjectId(tid)
        except: return {"msg": "Bad ID"}, 400
        res = db_core.get_collection("transactions").update_one(
            {"_id": oid, "status": "pending"},
            {"$set": {"status": "rejected", "rejected_by": admin, "reason": rsn}}
        )
        return ({"msg": "Rejected"}, 200) if res.modified_count else ({"msg": "Not found"}, 404)

    job = worker_engine.submit_job(_reject, tx_id, g.current_user["username"], reason, wait=True)
    if job.get("finished"):
        res, code = job["result"]
        return jsonify(res), code
    return jsonify({"msg": "Queued"}), 202

@app.route("/admin/coupons", methods=["POST"])
@admin_required
def create_coupon():
    json_data = request.get_json(silent=True)
    if not json_data: return jsonify({"msg": "JSON required"}), 400
    try: data = CouponSchema().load(json_data)
    except ValidationError as e: return jsonify(e.messages), 400
    
    try:
        db_core.get_collection("coupons").insert_one({
            **data, "uses": 0, "used_by": [], "created_at": get_utc_now()
        })
        return jsonify({"msg": "Created"}), 201
    except DuplicateKeyError:
        return jsonify({"msg": "Code exists"}), 409

# ----- BOOTSTRAP -----
def init_app():
    worker_engine.start()
    db = db_core.get_db()
    db.users.create_index("username", unique=True)
    db.coupons.create_index("code", unique=True)
    if AppConfig.ADMIN_ENV_USER:
        try:
            db.users.insert_one({
                "username": AppConfig.ADMIN_ENV_USER.lower(),
                "password": hash_password(AppConfig.ADMIN_ENV_PASS),
                "role": "admin",
                "created_at": get_utc_now()
            })
            logger.info("Admin Bootstrapped")
        except DuplicateKeyError: pass

atexit.register(worker_engine.stop)

if __name__ == "__main__":
    init_app()
    app.run(host="0.0.0.0", port=AppConfig.APP_PORT, debug=False)
