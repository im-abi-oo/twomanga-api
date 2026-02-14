import os
import datetime
import bcrypt
import requests
import json
import uuid
import threading
import time
from functools import wraps
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS 
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, JWTManager, get_jwt, verify_jwt_in_request
)
from bson.objectid import ObjectId
from pymongo import ASCENDING, DESCENDING
from dotenv import load_dotenv

# --- بارگذاری تنظیمات محیطی ---
load_dotenv()

app = Flask(__name__)

# --- پیکربندی CORS هوشمند ---
raw_origins = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()] if raw_origins else "*"
CORS(app, resources={r"/*": {"origins": allowed_origins}}) 

# --- پیکربندی اپلیکیشن ---
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_IDS = [idx.strip() for idx in os.getenv("ADMIN_IDS", "").split(",") if idx.strip()]
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID")
APP_PORT = int(os.getenv("PORT", 5001))

mongo = PyMongo(app)
jwt = JWTManager(app)

# --- [توابع کمکی دیتابیس و امنیت] ---

def setup_database():
    """ایجاد ایندکس‌ها برای سرعت و جلوگیری از دیتای تکراری"""
    with app.app_context():
        try:
            mongo.db.users.create_index([("username", ASCENDING)], unique=True)
            mongo.db.users.create_index([("telegram_id", ASCENDING)], unique=True)
            mongo.db.transactions.create_index([("tx_hash", ASCENDING)], unique=True)
            mongo.db.coupons.create_index([("code", ASCENDING)], unique=True)
            print("✅ دیتابیس با موفقیت پیکربندی و ایندکس‌گذاری شد.")
        except Exception as e:
            print(f"❌ خطا در ایندکس‌گذاری دیتابیس: {e}")

def single_session_required(fn):
    """جلوگیری از استفاده همزمان چند نفر از یک اکانت"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user = mongo.db.users.find_one({"username": get_jwt_identity()}, {"session_salt": 1})
            if not user or get_jwt().get("session_salt") != user.get("session_salt"):
                return jsonify({"msg": "سشن شما منقضی شده یا دستگاه دیگری وارد شده است"}), 401
            return fn(*args, **kwargs)
        except:
            return jsonify({"msg": "خطا در احراز هویت"}), 401
    return wrapper

def send_tg(chat_id, text, markup=None):
    """ارسال پیام به تلگرام"""
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
    if markup: payload['reply_markup'] = json.dumps(markup)
    try: requests.post(url, json=payload, timeout=10)
    except: pass

# --- [بخش API های احراز هویت و کاربر] ---

@app.route('/')
def home():
    return "🚀 Two Manga API is running in Production Mode!", 200

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    u = data.get('username', '').strip().lower()
    p = data.get('password')
    t = data.get('telegram_id', '').strip()

    if not all([u, p, t]) or len(p) < 6:
        return jsonify({"msg": "اطلاعات ناقص است یا رمز عبور بسیار کوتاه است"}), 400
    
    hp = bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt())
    try:
        mongo.db.users.insert_one({
            'username': u, 'password': hp, 'telegram_id': t,
            'expiryDate': None, 'session_salt': str(uuid.uuid4()),
            'total_purchases': 0, 'created_at': datetime.datetime.utcnow()
        })
        return jsonify({"msg": "ثبت‌نام با موفقیت انجام شد"}), 201
    except:
        return jsonify({"msg": "نام کاربری یا آیدی تلگرام قبلاً ثبت شده است"}), 409

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    u, p = data.get('username','').strip().lower(), data.get('password')
    user = mongo.db.users.find_one({'username': u})
    
    if user and bcrypt.checkpw(p.encode('utf-8'), user['password']):
        salt = str(uuid.uuid4())
        mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'session_salt': salt}})
        at = create_access_token(identity=u, additional_claims={"session_salt": salt})
        rt = create_refresh_token(identity=u, additional_claims={"session_salt": salt})
        return jsonify(access_token=at, refresh_token=rt), 200
    
    return jsonify({"msg": "نام کاربری یا رمز عبور اشتباه است"}), 401

@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    u = get_jwt_identity()
    user = mongo.db.users.find_one({"username": u}, {"session_salt": 1})
    if not user: return jsonify({"msg": "کاربر یافت نشد"}), 401
    at = create_access_token(identity=u, additional_claims={"session_salt": user['session_salt']})
    return jsonify(access_token=at), 200

@app.route('/api/user/status', methods=['GET'])
@jwt_required()
@single_session_required
def get_status():
    user = mongo.db.users.find_one({'username': get_jwt_identity()})
    now = datetime.datetime.utcnow()
    exp = user.get('expiryDate')
    is_premium = exp and exp > now
    
    return jsonify({
        "username": user['username'],
        "is_premium": bool(is_premium),
        "days_left": (exp - now).days if is_premium else 0,
        "expiry_date": exp.isoformat() if exp else None,
        "total_purchases": user.get('total_purchases', 0)
    }), 200

# --- [بخش مالی و پرداخت] ---

@app.route('/payment/submit', methods=['POST'])
@jwt_required()
@single_session_required
def submit_payment():
    u_name = get_jwt_identity()
    user = mongo.db.users.find_one({'username': u_name})
    data = request.get_json()
    tx_hash = data.get('tx_hash','').strip()
    coupon = data.get('coupon_code','').strip()
    days = int(data.get('days', 30))
    
    # بررسی کوپن هدیه
    if coupon:
        c = mongo.db.coupons.find_one({"code": coupon})
        if c:
            now = datetime.datetime.utcnow()
            start = user['expiryDate'] if (user.get('expiryDate') and user['expiryDate'] > now) else now
            new_exp = start + datetime.timedelta(days=c['bonus_days'])
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'expiryDate': new_exp}})
            mongo.db.coupons.delete_one({"_id": c['_id']})
            send_tg(user['telegram_id'], f"🎁 **کد هدیه فعال شد!**\nاعتبار جدید تا: `{new_exp.strftime('%Y-%m-%d')}`")
            return jsonify({"msg": "کد هدیه با موفقیت اعمال شد"}), 200
        return jsonify({"msg": "کد هدیه نامعتبر یا منقضی است"}), 400

    # بررسی هش تراکنش
    if not tx_hash or len(tx_hash) < 10 or mongo.db.transactions.find_one({"tx_hash": tx_hash}):
        return jsonify({"msg": "هش تراکنش نامعتبر یا تکراری است"}), 400

    tx_id = mongo.db.transactions.insert_one({
        "user_id": user['_id'], "username": u_name, "tx_hash": tx_hash,
        "days": days, "status": "pending", "created_at": datetime.datetime.utcnow()
    }).inserted_id

    # دکمه‌های شیک مدیریت برای ادمین
    kb = {"inline_keyboard": [
        [{"text": "✅ تایید پرداخت", "callback_data": f"appr:{tx_id}"}],
        [{"text": "❌ رد درخواست", "callback_data": f"rejt:{tx_id}"}]
    ]}
    
    for admin in ADMIN_IDS:
        send_tg(admin, f"💰 **درخواست ارتقا حساب**\n\n👤 کاربر: `{u_name}`\n🗓 پلن: `{days} روزه`\n🔗 هش: `{tx_hash}`", kb)
    
    return jsonify({"msg": "درخواست شما ثبت شد و پس از تایید ادمین فعال خواهد شد"}), 200

# --- [موتور پردازش پس‌زمینه (بات و مانیتورینگ)] ---

def telegram_bot_engine():
    """شنود دکمه‌های ادمین و دستورات تلگرام"""
    print("🤖 Bot Engine is running...")
    offset = 0
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?offset={offset}&timeout=20"
            resp = requests.get(url, timeout=25).json()
            if not resp.get("ok"): continue
            
            for update in resp.get("result", []):
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    cq = update["callback_query"]
                    data = cq["data"]
                    action = "approve" if data.startswith("appr:") else "reject"
                    tx_id_str = data.split(":")[1]
                    
                    with app.app_context():
                        tx = mongo.db.transactions.find_one({'_id': ObjectId(tx_id_str), 'status': 'pending'})
                        if tx:
                            user = mongo.db.users.find_one({'_id': tx['user_id']})
                            if action == "approve":
                                now = datetime.datetime.utcnow()
                                start = user['expiryDate'] if (user.get('expiryDate') and user['expiryDate'] > now) else now
                                new_exp = start + datetime.timedelta(days=tx['days'])
                                
                                mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'expiryDate': new_exp}, '$inc': {'total_purchases': 1}})
                                mongo.db.transactions.update_one({'_id': tx['_id']}, {'$set': {'status': 'approved', 'processed_at': now}})
                                
                                send_tg(user['telegram_id'], f"✅ **پرداخت تایید شد!**\nاشتراک شما تا تاریخ `{new_exp.strftime('%Y-%m-%d')}` فعال شد.")
                                if LOG_CHANNEL_ID:
                                    send_tg(LOG_CHANNEL_ID, f"📢 #فروش\nکاربر: `{user['username']}`\nمدت: {tx['days']} روز")
                            else:
                                mongo.db.transactions.update_one({'_id': tx['_id']}, {'$set': {'status': 'rejected'}})
                                send_tg(user['telegram_id'], "❌ **پرداخت رد شد**\nتراکنش شما توسط ادمین تایید نشد. در صورت نیاز به پشتیبانی پیام دهید.")
                    
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", 
                                 json={"callback_query_id": cq["id"], "text": "انجام شد"})
        except: time.sleep(5)

def health_monitor():
    """گزارش سلامت دیتابیس و آمار روزانه"""
    while True:
        time.sleep(86400) # هر ۲۴ ساعت
        with app.app_context():
            try:
                total_u = mongo.db.users.count_documents({})
                sales_24 = mongo.db.transactions.count_documents({"status": "approved", "processed_at": {"$gte": datetime.datetime.utcnow() - datetime.timedelta(hours=24)}})
                report = f"📊 **گزارش روزانه سیستم**\n\n👥 کل کاربران: `{total_u}`\n💰 فروش ۲۴ ساعت: `{sales_24}`\n✅ وضعیت دیتابیس: `OK`"
                for admin in ADMIN_IDS: send_tg(admin, report)
            except Exception as e:
                for admin in ADMIN_IDS: send_tg(admin, f"⚠️ خطا در مانیتورینگ: {e}")

# --- [مدیریت خطاهای سرور] ---

@app.errorhandler(Exception)
def handle_global_exception(e):
    if hasattr(e, 'code') and e.code in [404, 405]: return jsonify({"msg": "Endpoint not found"}), e.code
    err_trace = traceback.format_exc()
    for admin in ADMIN_IDS:
        send_tg(admin, f"🆘 **CRITICAL BACKEND ERROR**\n`{str(e)}`")
    print(err_trace)
    return jsonify({"msg": "خطای داخلی سرور"}), 500

if __name__ == '__main__':
    setup_database()
    # شروع تردها برای پردازش همزمان
    threading.Thread(target=telegram_bot_engine, daemon=True).start()
    threading.Thread(target=health_monitor, daemon=True).start()
    
    app.run(host='0.0.0.0', port=APP_PORT, debug=False)
