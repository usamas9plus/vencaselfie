from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import uuid
import os
import json
import hashlib
import base64
import secrets
from datetime import datetime
from upstash_redis import Redis

app = Flask(__name__)
# Enable CORS so your admin.html can communicate with this Vercel API
CORS(app)

# --- CONFIGURATION ---
# Initialize Upstash Redis via Environment Variables
try:
    redis = Redis.from_env()
except Exception as e:
    print(f"Warning: Redis not initialized. Check Env Vars. Error: {e}")
    redis = None

# Keep Env vars as fallback for legacy keys
ALLOWED_LICENSE_KEYS_JSON = os.environ.get('ALLOWED_LICENSE_KEYS', '{}')
ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET')

def get_fingerprint_hash(fingerprint_data):
    """Creates a consistent SHA-256 hash of the PC hardware fingerprint."""
    if not fingerprint_data:
        return None
    # Sort keys to ensure consistent hashing regardless of dictionary order
    canonical_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

def _validate_license_logic(license_key):
    """
    Validates key against Redis (Dynamic) first, then Environment Variables (Legacy).
    """
    if not license_key:
        return False, "License key is required", None
    
    expiry_timestamp_ms = None
    
    # --- STRATEGY 1: CHECK REDIS (DATABASE) ---
    if redis:
        redis_key = f"license_data:{license_key}"
        stored_data = redis.get(redis_key)
        
        if stored_data:
            try:
                if isinstance(stored_data, str):
                    key_info = json.loads(stored_data)
                else:
                    key_info = stored_data 
                
                expiry_str = key_info.get("expiry")
                
                if expiry_str:
                    expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
                    if datetime.now() > expiry_date:
                        return False, "License key has expired. Please renew!", None
                    expiry_timestamp_ms = expiry_date.timestamp() * 1000
                else:
                    expiry_timestamp_ms = (time.time() * 1000) + 31536000000
                
                return True, "Valid", expiry_timestamp_ms
            except Exception as e:
                print(f"Error parsing redis license data: {e}")

    # --- STRATEGY 2: CHECK ENV VARS (LEGACY FALLBACK) ---
    try:
        allowed_keys_map = json.loads(ALLOWED_LICENSE_KEYS_JSON)
    except json.JSONDecodeError:
        allowed_keys_map = {}
    
    if license_key in allowed_keys_map:
        expiry_str = allowed_keys_map[license_key]
        try:
            expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
            if datetime.now() > expiry_date:
                return False, "License key has expired. Please renew!", None
            expiry_timestamp_ms = expiry_date.timestamp() * 1000
        except ValueError:
            expiry_timestamp_ms = (time.time() * 1000) + 31536000000
        return True, "Valid", expiry_timestamp_ms

    return False, "Invalid license key.", None

# --- ROUTES ---

@app.route('/')
def index():
    return "403 Forbidden"

@app.route('/version')
def version():
    return jsonify({
        "version": "2.0.1", 
        "backend": "upstash-redis",
        "features": ["migration_tool", "dynamic_keys", "device_locking", "usage_tracking", "admin_reset", "CORS"],
        "timestamp": time.time()
    })

# --- ADMIN ENDPOINTS ---

@app.route('/api/admin/migrate_legacy_keys', methods=['POST'])
def admin_migrate_legacy_keys():
    """Moves keys from Env Vars to Redis Database."""
    try:
        data = request.json or {}
        admin_secret = data.get('admin_secret')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        # Read Legacy Keys
        try:
            allowed_keys_map = json.loads(ALLOWED_LICENSE_KEYS_JSON)
        except:
            return jsonify({"success": False, "message": "Could not parse ALLOWED_LICENSE_KEYS env var"}), 400

        migrated_count = 0
        skipped_count = 0

        # Migrate Loop
        for license_key, expiry_date in allowed_keys_map.items():
            redis_key = f"license_data:{license_key}"
            
            # Only add if it doesn't exist in Redis yet
            if not redis.exists(redis_key):
                license_data = {
                    "expiry": expiry_date,
                    "created_at": time.time(),
                    "status": "active",
                    "source": "legacy_migration"
                }
                redis.set(redis_key, json.dumps(license_data))
                migrated_count += 1
            else:
                skipped_count += 1
        
        return jsonify({
            "success": True, 
            "message": f"Migration complete. Migrated: {migrated_count}, Skipped (Already in DB): {skipped_count}"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/generate_license', methods=['POST'])
def admin_generate_license():
    try:
        data = request.json or {}
        admin_secret = data.get('admin_secret')
        expiry_date = data.get('expiry') 
        custom_key = data.get('custom_key')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
            
        if not expiry_date:
            return jsonify({"success": False, "message": "Expiry date required"}), 400

        try:
            datetime.strptime(expiry_date, "%Y-%m-%d")
        except ValueError:
             return jsonify({"success": False, "message": "Invalid date format. Use YYYY-MM-DD"}), 400

        if custom_key:
            new_license_key = custom_key
        else:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            new_license_key = "-".join([''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)])

        license_data = {
            "expiry": expiry_date,
            "created_at": time.time(),
            "status": "active"
        }
        
        redis_key = f"license_data:{new_license_key}"
        
        if redis.exists(redis_key) and not custom_key:
            return jsonify({"success": False, "message": "Collision detected, try again."}), 500
            
        redis.set(redis_key, json.dumps(license_data))

        return jsonify({
            "success": True, 
            "message": "License generated successfully",
            "license_key": new_license_key,
            "expiry": expiry_date
        })

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/list_licenses', methods=['POST'])
def admin_list_licenses():
    try:
        data = request.json or {}
        admin_secret = data.get('admin_secret')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        licenses = []
        cursor = '0'
        
        while True:
            cursor, keys = redis.scan(cursor=cursor, match='license_data:*', count=100)
            
            for key in keys:
                key_name = key.split("license_data:")[1]
                val = redis.get(key)
                info = json.loads(val) if isinstance(val, str) else val
                
                usage_count = redis.get(f"usage_count:{key_name}") or 0
                is_locked = redis.exists(f"license_lock:{key_name}")
                
                licenses.append({
                    "key": key_name,
                    "expiry": info.get('expiry', 'N/A'),
                    "created_at": info.get('created_at', 0),
                    "usage": int(usage_count),
                    "locked": bool(is_locked)
                })

            if cursor == 0 or cursor == '0':
                break

        licenses.sort(key=lambda x: x['created_at'], reverse=True)
        return jsonify({"success": True, "licenses": licenses})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/reset_license', methods=['POST'])
def admin_reset_license():
    try:
        data = request.json or {}
        license_key = data.get('license_key')
        admin_secret = data.get('admin_secret')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        lock_key = f"license_lock:{license_key}"
        if redis and redis.exists(lock_key):
            redis.delete(lock_key)
            return jsonify({"success": True, "message": f"Device lock reset for {license_key}"})
        return jsonify({"success": False, "message": "No lock found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/get_history', methods=['POST'])
def admin_get_history():
    try:
        data = request.json or {}
        license_key = data.get('license_key')
        admin_secret = data.get('admin_secret')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        history_key = f"usage_history:{license_key}"
        raw_history = redis.lrange(history_key, 0, 19) 
        history = [json.loads(h) for h in raw_history]
        
        return jsonify({"success": True, "history": history})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/delete_license', methods=['POST'])
def admin_delete_license():
    try:
        data = request.json or {}
        license_key = data.get('license_key')
        admin_secret = data.get('admin_secret')

        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        pipeline = redis.pipeline()
        pipeline.delete(f"license_data:{license_key}")
        pipeline.delete(f"license_lock:{license_key}")
        pipeline.delete(f"usage_count:{license_key}")
        pipeline.delete(f"usage_history:{license_key}")
        pipeline.exec()
        
        return jsonify({"success": True, "message": f"Permanently deleted {license_key}"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# --- CORE LOGIC ---

@app.route('/api/activate_license', methods=['POST'])
def activate_license():
    try:
        try:
            raw_data = request.data.decode('utf-8')
            data = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except:
            data = request.json or {}
            
        license_key = data.get('license_key')
        pc_fingerprint = data.get('pc_fingerprint_data')
        
        if not redis: return jsonify({"success": False, "message": "DB Unavailable"}), 500
        if not pc_fingerprint: return jsonify({"success": False, "message": "Security Error"}), 400

        is_valid, msg, expiry_ms = _validate_license_logic(license_key)
        if not is_valid: return jsonify({"success": False, "message": msg}), 403

        incoming_hash = get_fingerprint_hash(pc_fingerprint)
        lock_key = f"license_lock:{license_key}"
        stored_hash = redis.get(lock_key)
        
        if stored_hash and stored_hash != incoming_hash:
            return jsonify({"success": False, "message": "Only 1 Device allowed"}), 403
        elif not stored_hash:
            redis.set(lock_key, incoming_hash)

        activation_token = f"tok_{uuid.uuid4().hex}"
        response_data = {
            "success": True,
            "activationToken": activation_token,
            "licenseId": 1001,
            "status": "valid",
            "expiryDate": expiry_ms
        }
        return base64.b64encode(json.dumps(response_data).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/create_session', methods=['POST'])
def create_session():
    try:
        try:
            raw_data = request.data.decode('utf-8')
            data = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except:
            data = request.json or {}
        
        license_key = data.get('license_key')
        pc_fingerprint = data.get('pc_fingerprint_data')
        
        if not redis: return jsonify({"success": False, "message": "DB Unavailable"}), 500
        
        is_valid, msg, _ = _validate_license_logic(license_key)
        if not is_valid: return jsonify({"success": False, "message": msg}), 403

        incoming_hash = get_fingerprint_hash(pc_fingerprint)
        stored_hash = redis.get(f"license_lock:{license_key}")

        if not stored_hash or stored_hash != incoming_hash:
            return jsonify({"success": False, "message": "Only 1 Device is Allowed, Please login on previous device."}), 403

        redis.incr(f"usage_count:{license_key}")
        usage_event = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": request.remote_addr}
        redis.lpush(f"usage_history:{license_key}", json.dumps(usage_event))
        redis.ltrim(f"usage_history:{license_key}", 0, 49)

        server_url = data.get('server_url', request.host_url.rstrip('/'))
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        session_data = {
            "session_id": session_id,
            "status": "CREATED", 
            "created_at": time.time(),
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'),
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
            "event_session_id": None,
            "server_url": server_url
        }
        redis.set(session_id, json.dumps(session_data), ex=86400)
        
        response_data = {
            "success": True, 
            "session_id": session_id,
            "client_selfie_link": f"{server_url}/selfie/?session={session_id}"
        }
        return base64.b64encode(json.dumps(response_data).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/get_selfie_data.php', methods=['POST'])
def get_selfie_data():
    try:
        try: raw_data = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except: payload = request.json or {}
        session_id = payload.get('session')
        session_data_str = redis.get(session_id) if redis else None
        if not session_data_str: return jsonify({"success": False, "message": "Session expired"})
        session = json.loads(session_data_str)
        response_data = {
            "success": True,
            "data": {
                "user_id": session.get('user_id'),
                "transaction_id": session.get('transaction_id'),
                "proxy_host": session.get('proxy'),
                "status": session.get('status'),
                "server_url": session.get('server_url', request.host_url.rstrip('/'))
            }
        }
        return base64.b64encode(json.dumps(response_data).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/update_status.php', methods=['POST'])
def update_status():
    try:
        try: raw_data = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except: payload = request.json or {}
        session_id = payload.get('session_id')
        new_status = payload.get('new_status')
        session_data_str = redis.get(session_id) if redis else None
        if session_data_str:
            session = json.loads(session_data_str)
            session['status'] = new_status
        else:
            session = {"session_id": session_id, "status": new_status, "created_at": time.time(), "is_skeleton": True}
        if redis: redis.set(session_id, json.dumps(session), ex=86400)
        return jsonify({"success": True, "message": "Status updated"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/submit_liveness.php', methods=['POST'])
def submit_liveness():
    try:
        try: raw_data = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except: payload = request.json or {}
        session_id = payload.get('session_id')
        event_session_id = payload.get('event_session_id')
        session_data_str = redis.get(session_id) if redis else None
        if session_data_str:
            session = json.loads(session_data_str)
            session['status'] = 'COMPLETED'
            session['event_session_id'] = event_session_id
        else:
            session = {"session_id": session_id, "status": 'COMPLETED', "event_session_id": event_session_id, "created_at": time.time(), "is_skeleton": True}
        if redis: redis.set(session_id, json.dumps(session), ex=86400)
        return jsonify({"success": True, "message": "Liveness submitted"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/check_session_status', methods=['POST'])
def check_session_status():
    try:
        try: raw_data = request.data.decode('utf-8'); payload = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        except: payload = request.json or {}
        session_id = payload.get('session_id')
        session_data_str = redis.get(session_id) if redis else None
        if not session_data_str: return jsonify({"success": False, "message": "Session not found"})
        session = json.loads(session_data_str)
        response_data = {
            "success": True,
            "data": {"status": session.get('status'), "event_session_id": session.get('event_session_id')}
        }
        return base64.b64encode(json.dumps(response_data).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/selfie/')
def selfie_page():
    return """
    <html>
    <head>
        <title>Vecna Selfie - Copy and Open this link in Kiwi/Quetta Browser</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');
            body { 
                margin: 0; padding: 0; height: 100vh; width: 100vw; overflow: hidden; 
                background: radial-gradient(circle at center, #2b0000 0%, #000000 100%); 
                color: white; font-family: 'Orbitron', sans-serif; 
                display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; 
            }
            h1 { font-size: 2.5em; color: #ff0000; text-shadow: 0 0 10px #ff0000; margin-bottom: 20px; }
            .loader { width: 80px; height: 80px; border: 5px solid #8b0000; border-top: 5px solid #ff0000; border-radius: 50%; animation: spin 1s linear infinite; margin-bottom: 30px; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <div class="loader"></div>
        <h1>Vecna Selfie</h1>
        <h2>Extension is NOT Installed!</h2>
        <p>It looks like you have NOT installed the Vecna Selfie Client Extension please install the extension to continue</p>
        <a href="https://chromewebstore.google.com/detail/vecna-selfie-client-remot/mcmlkpnkmomgiolpfagpamcihppjpphg">
  <h2>Click here to install the Client Extension</h2>
</a>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

