from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
import time
import uuid
import os
import json
import hashlib
import base64
import secrets
from datetime import datetime, timedelta
from upstash_redis import Redis
import requests
import threading

app = Flask(__name__)
CORS(app)

# --- CONFIGURATION ---
try:
    redis = Redis.from_env()
except Exception as e:
    print(f"Warning: Redis not initialized. Check Env Vars. Error: {e}")
    redis = None

ALLOWED_LICENSE_KEYS_JSON = os.environ.get('ALLOWED_LICENSE_KEYS', '{}')
ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET')

# --- TELEGRAM BOT CONFIG ---
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')

# --- HELPERS ---

def check_and_set_alert_lock(lock_name, expire=30):
    """Checks if a lock exists in Redis, if not, sets it and returns True (can alert)."""
    if not redis:
        return True  # Fallback if Redis is down
    try:
        rk = f"alert_lock:{lock_name}"
        # set(..., nx=True) returns True if it set the key, False if it already existed
        return redis.set(rk, "1", nx=True, ex=expire)
    except:
        return True

def send_telegram_alert(message):
    """Sends an asynchronous, non-blocking telegram alert"""
    def _send():
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": "HTML"
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            print(f"Telegram Alert Error: {e}")

    threading.Thread(target=_send).start()

def mask_license_key(key):
    """Masks the middle part of a license key"""
    if not key: return ""
    parts = key.split('-')
    if len(parts) >= 3:
        # e.g. VECNA-USAMA-1208 -> VECNA-*****-1208
        # or VECNA-XXXX-XXXX-1208 -> VECNA-*****-*****-1208
        masked_middle = "-".join(["*****" for _ in parts[1:-1]])
        return f"{parts[0]}-{masked_middle}-{parts[-1]}"
    if len(key) > 8:
        return f"{key[:4]}****{key[-4:]}"
    return key

def get_pkt_time():
    """Returns the current time in Pakistan Standard Time (UTC+5)"""
    pkt = datetime.utcnow() + timedelta(hours=5)
    return pkt.strftime("%d-%B-%Y %I:%M %p")

def get_fingerprint_hash(fingerprint_data):
    if not fingerprint_data: return None
    canonical_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

def update_last_activity(license_key):
    if not redis: return
    try:
        rk = f"license_data:{license_key}"
        data_str = redis.get(rk)
        if data_str:
            data = json.loads(data_str) if isinstance(data_str, str) else data_str
            data['last_activity'] = time.time()
            redis.set(rk, json.dumps(data))
    except: pass

def _validate_license_logic(license_key):
    if not license_key: return False, "License key is required", None
    
    expiry_timestamp_ms = None
    
    if redis:
        rk = f"license_data:{license_key}"
        stored = redis.get(rk)
        if stored:
            try:
                info = json.loads(stored) if isinstance(stored, str) else stored
                if info.get("key_category", "regular") == "regular":
                    payment_status = info.get("payment_status", "Payment Received")
                    if payment_status == "Payment Suspended":
                        return False, "System has automatically suspended your key as your payment is still pending, Please make the payment to continue", None
                    elif payment_status == "Payment Pending":
                        pending_since = info.get("payment_pending_since", info.get("created_at", time.time()))
                        if time.time() - pending_since > 3 * 24 * 60 * 60:
                            return False, "System has automatically suspended your key as your payment is still pending, Please make the payment to continue", None

                if info.get('type') == 'floating' and info.get('status') == 'unused':
                    return True, "Ready to activate", None
                expiry_str = info.get("expiry")
                if expiry_str:
                    try:
                        expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
                    if datetime.now() > expiry_date: return False, "License key has expired. Please renew to continue", None
                    expiry_timestamp_ms = expiry_date.timestamp() * 1000
                else: expiry_timestamp_ms = (time.time() * 1000) + 31536000000
                return True, "Valid", expiry_timestamp_ms
            except: pass

    try: allowed_keys = json.loads(ALLOWED_LICENSE_KEYS_JSON)
    except: allowed_keys = {}
    
    if license_key in allowed_keys:
        try:
            try:
                expiry_date = datetime.strptime(allowed_keys[license_key], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                expiry_date = datetime.strptime(allowed_keys[license_key], "%Y-%m-%d")
            if datetime.now() > expiry_date: return False, "License key has expired. Please renew to continue", None
            expiry_timestamp_ms = expiry_date.timestamp() * 1000
        except: expiry_timestamp_ms = (time.time() * 1000) + 31536000000
        return True, "Valid", expiry_timestamp_ms

    return False, "Invalid license key. Please enter a valid license key.", None

# --- ROUTES ---

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/version')
def version():
    return jsonify({"version": "2.6.1", "features": ["scan_fix", "activity_tracking"]})

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/favicon.ico')
def favicon():
    try:
        return send_from_directory('static', 'favicon.ico')
    except:
        return '', 204

@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

# --- ADMIN ---

@app.route('/api/admin/migrate_legacy_keys', methods=['POST'])
def admin_migrate_legacy_keys():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        try: allowed = json.loads(ALLOWED_LICENSE_KEYS_JSON)
        except: return jsonify({"success": False}), 400

        m, s = 0, 0
        for k, v in allowed.items():
            rk = f"license_data:{k}"
            if not redis.exists(rk):
                redis.set(rk, json.dumps({"expiry": v, "created_at": time.time(), "status": "active"}))
                m += 1
            else: s += 1
        return jsonify({"success": True, "message": f"Migrated: {m}, Skipped: {s}"})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/generate_license', methods=['POST'])
def admin_generate_license():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        custom = data.get('custom_key')
        is_floating = data.get('is_floating', False)
        key_category = data.get('key_category', 'regular')  # 'test' or 'regular'
        
        if custom: new_key = custom
        else:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            new_key = "-".join([''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)])

        payment_status = "Payment Pending" if key_category == "regular" else "Payment Received"
        lic_data = {
            "created_at": time.time(),
            "status": "unused" if is_floating else "active",
            "type": "floating" if is_floating else "fixed",
            "key_category": key_category,
            "last_activity": None,
            "label": data.get('label', ''),
            "payment_status": payment_status
        }
        if payment_status == "Payment Pending":
            lic_data["payment_pending_since"] = time.time()
        
        if is_floating:
            if not data.get('duration_days'): return jsonify({"success": False}), 400
            lic_data['duration_days'] = int(data.get('duration_days'))
        else:
            if not data.get('expiry'): return jsonify({"success": False}), 400
            lic_data['expiry'] = data.get('expiry') + datetime.now().strftime(" %H:%M:%S")

        rk = f"license_data:{new_key}"
        if redis.exists(rk) and not custom: return jsonify({"success": False, "message": "Collision"}), 500
        
        redis.set(rk, json.dumps(lic_data))
        return jsonify({"success": True, "license_key": new_key})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/update_expiry', methods=['POST'])
def admin_update_expiry():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        rk = f"license_data:{data.get('license_key')}"
        if not redis.exists(rk): return jsonify({"success": False}), 404
        
        stored = redis.get(rk)
        info = json.loads(stored) if isinstance(stored, str) else stored
        
        new_date = data.get('new_expiry')
        existing_expiry = info.get('expiry', '')
        if " " in existing_expiry:
            time_part = " " + existing_expiry.split(" ")[1]
        else:
            time_part = datetime.fromtimestamp(info.get('created_at', time.time())).strftime(" %H:%M:%S")
            
        info['expiry'] = f"{new_date}{time_part}"
        redis.set(rk, json.dumps(info))
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/list_licenses', methods=['POST'])
def admin_list_licenses():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False, "message": "Unauthorized"}), 401

        licenses = []
        cursor = '0'
        all_keys = []
        
        # --- FIXED INFINITE LOOP ---
        while True:
            cursor, keys = redis.scan(cursor=cursor, match='license_data:*', count=500)
            all_keys.extend(keys)
            # Safe break: convert cursor to string to handle '0' (str) or 0 (int)
            if str(cursor) == '0': 
                break
            
        if not all_keys: return jsonify({"success": True, "licenses": []})

        for i in range(0, len(all_keys), 50):
            chunk = all_keys[i:i+50]
            pipe = redis.pipeline()
            for k in chunk:
                kn = k.split("license_data:")[1]
                pipe.get(k)
                pipe.get(f"usage_count:{kn}")
                pipe.exists(f"active_session_lock:{kn}")
                pipe.scard(f"key_devices:{kn}")  # Get device count for this key
            res = pipe.exec()
            
            for j in range(0, len(res), 4):  # Now 4 items per key
                val = res[j]
                if not val: continue
                info = json.loads(val) if isinstance(val, str) else val
                
                usage = res[j+1]
                locked = res[j+2]
                device_count = res[j+3] or 0  # Number of unique devices
                
                exp = info.get('expiry', 'N/A')
                if info.get('type') == 'floating' and info.get('status') == 'unused':
                    exp = f"Floating ({info.get('duration_days')}d)"

                licenses.append({
                    "key": chunk[j // 4].split("license_data:")[1],
                    "expiry": exp,
                    "created_at": info.get('created_at', 0),
                    "usage": int(usage) if usage else 0,
                    "locked": bool(locked),
                    "last_activity": info.get('last_activity', None),
                    "label": info.get('label', ''),
                    "key_category": info.get('key_category', 'regular'),
                    "device_count": int(device_count),
                    "payment_status": info.get('payment_status', 'Payment Received'),
                    "liveness_status": info.get('liveness_status', 'N/A')
                })

        licenses.sort(key=lambda x: x['created_at'], reverse=True)
        return jsonify({"success": True, "licenses": licenses})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/update_payment_status', methods=['POST'])
def admin_update_payment_status():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        rk = f"license_data:{data.get('license_key')}"
        if not redis.exists(rk): return jsonify({"success": False}), 404
        
        stored = redis.get(rk)
        info = json.loads(stored) if isinstance(stored, str) else stored
        
        new_status = data.get('payment_status', 'Payment Received')
        if new_status == 'Payment Pending' and info.get('payment_status') != 'Payment Pending':
            info['payment_pending_since'] = time.time()
            
        info['payment_status'] = new_status
        redis.set(rk, json.dumps(info))
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/update_label', methods=['POST'])
def admin_update_label():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        rk = f"license_data:{data.get('license_key')}"
        if not redis.exists(rk): return jsonify({"success": False}), 404
        
        stored = redis.get(rk)
        info = json.loads(stored) if isinstance(stored, str) else stored
        info['label'] = data.get('label', '')
        redis.set(rk, json.dumps(info))
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/reset_license', methods=['POST'])
def admin_reset_license():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        redis.delete(f"active_session_lock:{data.get('license_key')}")
        return jsonify({"success": True})
    except: return jsonify({"success": False}), 500

@app.route('/api/admin/get_history', methods=['POST'])
def admin_get_history():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        hist = redis.lrange(f"usage_history:{data.get('license_key')}", 0, 19)
        return jsonify({"success": True, "history": [json.loads(h) for h in hist]})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/delete_license', methods=['POST'])
def admin_delete_license():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        k = data.get('license_key')
        pipe = redis.pipeline()
        pipe.delete(f"license_data:{k}")
        pipe.delete(f"active_session_lock:{k}")
        pipe.delete(f"usage_count:{k}")
        pipe.delete(f"usage_history:{k}")
        pipe.exec()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/set_ticker_message', methods=['POST'])
def admin_set_ticker_message():
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        
        message = data.get('message', '')
        redis.set("ticker_message", message)
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/get_ticker_message', methods=['GET'])
def get_ticker_message():
    try:
        msg = redis.get("ticker_message")
        return jsonify({"success": True, "message": msg if msg else ""})
    except: return jsonify({"success": False, "message": ""})

@app.route('/api/admin/clear_test_device', methods=['POST'])
def admin_clear_test_device():
    """Clear test key device restriction for a specific license key"""
    try:
        data = request.json or {}
        if data.get('admin_secret') != ADMIN_SECRET_KEY: return jsonify({"success": False}), 401
        k = data.get('license_key')
        
        # Get all devices that used this key
        devices = redis.smembers(f"key_devices:{k}")
        cleared = 0
        
        for device_hash in devices:
            # Check if this device is mapped to this key
            mapped_key = redis.get(f"test_key_device_map:{device_hash}")
            if mapped_key == k:
                redis.delete(f"test_key_device_map:{device_hash}")
                cleared += 1
        
        return jsonify({"success": True, "cleared": cleared})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

# --- CORE ---

@app.route('/api/activate_license', methods=['POST'])
def activate_license():
    try:
        try: raw = request.data.decode('utf-8'); data = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: data = request.json or {}
        
        key = data.get('license_key')
        pc_fp = data.get('pc_fingerprint_data')
        incoming_hash = get_fingerprint_hash(pc_fp)
        
        rk = f"license_data:{key}"
        stored = redis.get(rk) if redis else None
        key_category = 'regular'
        
        if stored:
            info = json.loads(stored) if isinstance(stored, str) else stored
            key_category = info.get('key_category', 'regular')
            
            # Test key device restriction check during activation
            # Check if device used a DIFFERENT test key before
            if key_category == 'test' and incoming_hash:
                previous_key = redis.get(f"test_key_device_map:{incoming_hash}")
                if previous_key and previous_key != key:
                    return jsonify({"success": False, "message": "Sorry, you have previously used a Test Key, If you liked the Vecna Selfie please consider purchasing!"}), 403
            
            if info.get('type') == 'floating' and info.get('status') == 'unused':
                info['expiry'] = (datetime.now() + timedelta(days=info.get('duration_days', 30))).strftime("%Y-%m-%d %H:%M:%S")
                info['status'] = 'active'
                info['activated_at'] = time.time()
                info['last_activity'] = time.time()
                redis.set(rk, json.dumps(info))
            else:
                update_last_activity(key)

        # CRITICAL FIX: Validate BEFORE tracking devices
        valid, msg, exp = _validate_license_logic(key)
        if not valid: 
            return jsonify({"success": False, "message": msg}), 403
        
        # Only track device if validation passed
        if stored and incoming_hash:
            redis.sadd(f"key_devices:{key}", incoming_hash)
            if key_category == 'test':
                redis.set(f"test_key_device_map:{incoming_hash}", key)

        pay_status = "Payment Received"
        if stored:
            try:
                info_dict = json.loads(stored) if isinstance(stored, str) else stored
                pay_status = info_dict.get('payment_status', 'Payment Received')
            except: pass

        return base64.b64encode(json.dumps({
            "success": True, "activationToken": f"tok_{uuid.uuid4().hex}", "expiryDate": exp, "paymentStatus": pay_status
        }).encode('utf-8')).decode('utf-8')
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/create_session', methods=['POST'])
def create_session():
    try:
        try: raw = request.data.decode('utf-8'); data = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: data = request.json or {}
        
        key = data.get('license_key')
        pc_fp = data.get('pc_fingerprint_data')
        
        valid, msg, _ = _validate_license_logic(key)
        if not valid: return jsonify({"success": False, "message": msg}), 403

        update_last_activity(key)

        incoming_hash = get_fingerprint_hash(pc_fp)
        
        # Get license info to check key_category
        rk = f"license_data:{key}"
        lic_data = redis.get(rk)
        key_category = 'regular'  # Default for backward compatibility
        if lic_data:
            lic_info = json.loads(lic_data) if isinstance(lic_data, str) else lic_data
            key_category = lic_info.get('key_category', 'regular')
        
        # Test key device restriction check
        # Check if device used a DIFFERENT test key before
        if key_category == 'test' and incoming_hash:
            previous_key = redis.get(f"test_key_device_map:{incoming_hash}")
            if previous_key and previous_key != key:
                return jsonify({"success": False, "message": "This device has already used a test key. Please purchase a regular license."}), 403
        
        lock_key = f"active_session_lock:{key}"
        server_url = data.get('server_url', request.host_url.rstrip('/'))
        sess_id = f"sess_{uuid.uuid4().hex[:16]}"
        
        sess_data = {
            "session_id": sess_id, "license_key": key, "fingerprint_hash": incoming_hash,
            "status": "CREATED", "created_at": time.time(), "server_url": server_url,
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'),
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
            "target_domain": data.get('selfie_data', {}).get('target_domain'),
            "target_path": data.get('selfie_data', {}).get('target_path'),
        }

        # Generate unique 4-digit short code
        def generate_short_code():
            for _ in range(10):  # Try up to 10 times to find unique code
                code = str(secrets.randbelow(9000) + 1000)  # 1000-9999
                if not redis.exists(f"short_code:{code}"):
                    return code
            return str(secrets.randbelow(9000) + 1000)  # Fallback

        if redis.set(lock_key, sess_id, nx=True, ex=300):
            redis.set(sess_id, json.dumps(sess_data), ex=86400)
            redis.incr(f"usage_count:{key}")
            redis.lpush(f"usage_history:{key}", json.dumps({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": request.remote_addr}))
            redis.ltrim(f"usage_history:{key}", 0, 49)
            
            # Device tracking
            if incoming_hash:
                redis.sadd(f"key_devices:{key}", incoming_hash)  # Track device for this key
                if key_category == 'test':
                    redis.set(f"test_key_device_map:{incoming_hash}", key)  # Map device to this key
            # Generate and store short code
            short_code = generate_short_code()
            client_link = f"{server_url}/selfie/?session={sess_id}"
            
            # Construct augmented link with encoded data for short code
            selfie_data = data.get('selfie_data', {})
            user_id = selfie_data.get('scraped_user_id', '')
            transaction_id = selfie_data.get('scraped_transaction_id', '')
            proxy = selfie_data.get('proxy_host_for_client_xff', 'unknown_ip')
            target_domain = selfie_data.get('target_domain', 'appointment.thespainvisa.com')
            target_path = selfie_data.get('target_path', '/Global/')
            
            # Encode the data for the augmented link
            import urllib.parse
            combined = f"scrap={user_id}+transaction={transaction_id}+proxy={proxy}+target_domain={target_domain}+target_path={urllib.parse.quote(target_path)}"
            encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
            augmented_link = f"https://vecnaselfie.com/selfie/?session={sess_id}/data/{encoded}"
            
            # Store the augmented link for the short code
            redis.set(f"short_code:{short_code}", json.dumps({"session_id": sess_id, "link": augmented_link}), ex=300)  # 5 min TTL
            
            # Send Telegram Alert
            is_real = not data.get('is_test_link') and user_id != 'c6c2aec5-0afb-403f-9a18-d4bf36052888'
            if is_real:
                if check_and_set_alert_lock(f"link_gen:{key}:{user_id}", expire=30):
                    now_pkt = get_pkt_time()
                    alert_msg = (
                        f"<b>🚀 NEW SELFIE LINK GENERATED!</b>\n\n"
                        f"<b>Key:</b> <code>{mask_license_key(key)}</code>\n"
                        f"<b>User:</b> <code>{user_id}</code>\n"
                        f"<b>Time:</b> <code>{now_pkt}</code>\n"
                    )
                    send_telegram_alert(alert_msg)
            
            return base64.b64encode(json.dumps({
                "success": True, "session_id": sess_id, "client_selfie_link": client_link, "short_code": short_code
            }).encode('utf-8')).decode('utf-8')

        locked_id = redis.get(lock_key)
        if locked_id:
            l_str = redis.get(locked_id)
            if l_str and json.loads(l_str).get('fingerprint_hash') == incoming_hash:
                redis.set(sess_id, json.dumps(sess_data), ex=86400)
                redis.set(lock_key, sess_id, ex=300)
                
                # Generate and store short code
                short_code = generate_short_code()
                client_link = f"{server_url}/selfie/?session={sess_id}"
                
                # Construct augmented link with encoded data for short code
                selfie_data = data.get('selfie_data', {})
                user_id = selfie_data.get('scraped_user_id', '')
                transaction_id = selfie_data.get('scraped_transaction_id', '')
                proxy = selfie_data.get('proxy_host_for_client_xff', 'unknown_ip')
                target_domain = selfie_data.get('target_domain', 'appointment.thespainvisa.com')
                target_path = selfie_data.get('target_path', '/Global/')
                
                # Encode the data for the augmented link
                import urllib.parse
                combined = f"scrap={user_id}+transaction={transaction_id}+proxy={proxy}+target_domain={target_domain}+target_path={urllib.parse.quote(target_path)}"
                encoded = base64.b64encode(combined.encode('utf-8')).decode('utf-8')
                augmented_link = f"https://vecnaselfie.com/selfie/?session={sess_id}/data/{encoded}"
                
                # Store the augmented link for the short code
                redis.set(f"short_code:{short_code}", json.dumps({"session_id": sess_id, "link": augmented_link}), ex=300)
                
                # Send Telegram Alert
                is_real = not data.get('is_test_link') and user_id != 'c6c2aec5-0afb-403f-9a18-d4bf36052888'
                if is_real:
                    if check_and_set_alert_lock(f"link_gen:{key}:{user_id}", expire=30):
                        now_pkt = get_pkt_time()
                        alert_msg = (
                            f"<b>🚀 NEW SELFIE LINK GENERATED!</b>\n\n"
                            f"<b>Key:</b> <code>{mask_license_key(key)}</code>\n"
                            f"<b>User:</b> <code>{user_id}</code>\n"
                            f"<b>Time:</b> <code>{now_pkt}</code>\n"
                        )
                        send_telegram_alert(alert_msg)
                
                return base64.b64encode(json.dumps({
                    "success": True, "session_id": sess_id, "client_selfie_link": client_link, "short_code": short_code
                }).encode('utf-8')).decode('utf-8')

        return jsonify({"success": False, "message": "Link already generated on Another Device please wait for it to complete or Click on RESET SELFIE SESSION DATA"}), 409
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/report_liveness', methods=['POST'])
def report_liveness():
    try:
        try: raw = request.data.decode('utf-8'); data = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: data = request.json or {}
        
        key = data.get('license_key')
        status = data.get('status')
        
        if not key or not status: return jsonify({"success": False, "message": "Missing data"}), 400
        
        valid, msg, _ = _validate_license_logic(key)
        if not valid: return jsonify({"success": False, "message": msg}), 403
        
        rk = f"license_data:{key}"
        stored = redis.get(rk)
        if not stored: return jsonify({"success": False, "message": "Key not found"}), 404
        
        info = json.loads(stored) if isinstance(stored, str) else stored
        info['liveness_status'] = status
        redis.set(rk, json.dumps(info))
        
        # Add to history
        hist_data = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": f"Liveness {status}"
        }
        redis.lpush(f"usage_history:{key}", json.dumps(hist_data))
        redis.ltrim(f"usage_history:{key}", 0, 49)
        
        # Send Telegram Alert
        is_real = not data.get('is_test_link') and key != 'c6c2aec5-0afb-403f-9a18-d4bf36052888'
        if is_real:
            if check_and_set_alert_lock(f"liveness:{key}:{status}", expire=30):
                status_icon = "🟢" if status == "Successful" else "🔴"
                alert_msg = (
                    f"<b>{status_icon} LIVENESS RESULT: {status.upper()}</b>\n\n"
                    f"<b>Key:</b> <code>{mask_license_key(key)}</code>\n"
                    f"<b>Time:</b> <code>{get_pkt_time()}</code>\n"
                )
                send_telegram_alert(alert_msg)
        
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/cancel_session', methods=['POST'])
def cancel_session():
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        
        sess_id = payload.get('session_id')
        sess_str = redis.get(sess_id)
        
        if sess_str:
            sess = json.loads(sess_str)
            key = sess.get('license_key')
            if key:
                update_last_activity(key)
                if redis.get(f"active_session_lock:{key}") == sess_id: redis.delete(f"active_session_lock:{key}")
            sess['status'] = 'CANCELLED'
            redis.set(sess_id, json.dumps(sess), ex=86400)
            return jsonify({"success": True})
        return jsonify({"success": False, "message": "Not found"}), 404
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/lookup_code', methods=['POST'])
def lookup_code():
    """Lookup a 4-digit short code and return the corresponding selfie link"""
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        
        code = payload.get('code', '').strip()
        
        # Validate code format
        if not code or len(code) != 4 or not code.isdigit():
            return jsonify({"success": False, "message": "Invalid code format. Please enter a 4-digit code."}), 400
        
        # Look up the code in Redis
        code_data = redis.get(f"short_code:{code}")
        
        if not code_data:
            return jsonify({"success": False, "message": "Code not found or expired. Please ask your agent for a new code."}), 404
        
        data = json.loads(code_data) if isinstance(code_data, str) else code_data
        
        return base64.b64encode(json.dumps({
            "success": True,
            "link": data.get('link'),
            "session_id": data.get('session_id')
        }).encode('utf-8')).decode('utf-8')
        
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

# --- HELPERS ---

@app.route('/api/get_selfie_data.php', methods=['POST'])
def get_selfie_data():
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        sess_str = redis.get(payload.get('session'))
        if not sess_str: return jsonify({"success": False})
        s = json.loads(sess_str)
        return base64.b64encode(json.dumps({
            "success": True, 
            "data": {"user_id": s.get('user_id'), "transaction_id": s.get('transaction_id'), "proxy_host": s.get('proxy'), "status": s.get('status'), "server_url": s.get('server_url', request.host_url.rstrip('/')), "target_domain": s.get('target_domain'), "target_path": s.get('target_path')}
        }).encode('utf-8')).decode('utf-8')
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/update_status.php', methods=['POST'])
def update_status():
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        sid = payload.get('session_id')
        s_str = redis.get(sid)
        if s_str:
            s = json.loads(s_str)
            s['status'] = payload.get('new_status')
            redis.set(sid, json.dumps(s), ex=86400)
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/submit_liveness.php', methods=['POST'])
def submit_liveness():
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        sid = payload.get('session_id')
        s_str = redis.get(sid)
        if s_str:
            s = json.loads(s_str)
            s['status'] = 'COMPLETED'
            s['event_session_id'] = payload.get('event_session_id')
            key = s.get('license_key')
            if key and redis.get(f"active_session_lock:{key}") == sid: redis.delete(f"active_session_lock:{key}")
            redis.set(sid, json.dumps(s), ex=86400)
        return jsonify({"success": True})
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/check_session_status', methods=['POST'])
def check_session_status():
    try:
        try: raw = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: payload = request.json or {}
        s_str = redis.get(payload.get('session_id'))
        if not s_str: return jsonify({"success": False})
        s = json.loads(s_str)
        return base64.b64encode(json.dumps({
            "success": True, "data": {"status": s.get('status'), "event_session_id": s.get('event_session_id')}
        }).encode('utf-8')).decode('utf-8')
    except Exception as e: return jsonify({"success": False, "message": str(e)}), 500

@app.route('/selfie/')
def selfie_page(): 
    return render_template('selfie.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
