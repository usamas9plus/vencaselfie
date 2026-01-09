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

# --- HELPERS ---

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
                if info.get('type') == 'floating' and info.get('status') == 'unused':
                    return True, "Ready to activate", None
                expiry_str = info.get("expiry")
                if expiry_str:
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
        
        if custom: new_key = custom
        else:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            new_key = "-".join([''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)])

        lic_data = {
            "created_at": time.time(),
            "status": "unused" if is_floating else "active",
            "type": "floating" if is_floating else "fixed",
            "last_activity": None
        }
        
        if is_floating:
            if not data.get('duration_days'): return jsonify({"success": False}), 400
            lic_data['duration_days'] = int(data.get('duration_days'))
        else:
            if not data.get('expiry'): return jsonify({"success": False}), 400
            lic_data['expiry'] = data.get('expiry')

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
        info['expiry'] = data.get('new_expiry')
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
            res = pipe.exec()
            
            for j in range(0, len(res), 3):
                val = res[j]
                if not val: continue
                info = json.loads(val) if isinstance(val, str) else val
                
                usage = res[j+1]
                locked = res[j+2]
                
                exp = info.get('expiry', 'N/A')
                if info.get('type') == 'floating' and info.get('status') == 'unused':
                    exp = f"Floating ({info.get('duration_days')}d)"

                licenses.append({
                    "key": chunk[j // 3].split("license_data:")[1],
                    "expiry": exp,
                    "created_at": info.get('created_at', 0),
                    "usage": int(usage) if usage else 0,
                    "locked": bool(locked),
                    "last_activity": info.get('last_activity', None)
                })

        licenses.sort(key=lambda x: x['created_at'], reverse=True)
        return jsonify({"success": True, "licenses": licenses})
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

# --- CORE ---

@app.route('/api/activate_license', methods=['POST'])
def activate_license():
    try:
        try: raw = request.data.decode('utf-8'); data = json.loads(base64.b64decode(raw).decode('utf-8'))
        except: data = request.json or {}
        
        key = data.get('license_key')
        rk = f"license_data:{key}"
        stored = redis.get(rk) if redis else None
        if stored:
            info = json.loads(stored) if isinstance(stored, str) else stored
            if info.get('type') == 'floating' and info.get('status') == 'unused':
                info['expiry'] = (datetime.now() + timedelta(days=info.get('duration_days', 30))).strftime("%Y-%m-%d")
                info['status'] = 'active'
                info['activated_at'] = time.time()
                info['last_activity'] = time.time()
                redis.set(rk, json.dumps(info))
            else:
                update_last_activity(key)

        valid, msg, exp = _validate_license_logic(key)
        if not valid: return jsonify({"success": False, "message": msg}), 403

        return base64.b64encode(json.dumps({
            "success": True, "activationToken": f"tok_{uuid.uuid4().hex}", "expiryDate": exp
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
        lock_key = f"active_session_lock:{key}"
        server_url = data.get('server_url', request.host_url.rstrip('/'))
        sess_id = f"sess_{uuid.uuid4().hex[:16]}"
        
        sess_data = {
            "session_id": sess_id, "license_key": key, "fingerprint_hash": incoming_hash,
            "status": "CREATED", "created_at": time.time(), "server_url": server_url,
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'),
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
        }

        if redis.set(lock_key, sess_id, nx=True, ex=300):
            redis.set(sess_id, json.dumps(sess_data), ex=86400)
            redis.incr(f"usage_count:{key}")
            redis.lpush(f"usage_history:{key}", json.dumps({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": request.remote_addr}))
            redis.ltrim(f"usage_history:{key}", 0, 49)
            return base64.b64encode(json.dumps({
                "success": True, "session_id": sess_id, "client_selfie_link": f"{server_url}/selfie/?session={sess_id}"
            }).encode('utf-8')).decode('utf-8')

        locked_id = redis.get(lock_key)
        if locked_id:
            l_str = redis.get(locked_id)
            if l_str and json.loads(l_str).get('fingerprint_hash') == incoming_hash:
                redis.set(sess_id, json.dumps(sess_data), ex=86400)
                redis.set(lock_key, sess_id, ex=300)
                return base64.b64encode(json.dumps({
                    "success": True, "session_id": sess_id, "client_selfie_link": f"{server_url}/selfie/?session={sess_id}"
                }).encode('utf-8')).decode('utf-8')

        return jsonify({"success": False, "message": "Link already generated on Another Device please wait for it to complete or Click on RESET SELFIE SESSION DATA"}), 409
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
            "data": {"user_id": s.get('user_id'), "transaction_id": s.get('transaction_id'), "proxy_host": s.get('proxy'), "status": s.get('status'), "server_url": s.get('server_url', request.host_url.rstrip('/'))}
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
