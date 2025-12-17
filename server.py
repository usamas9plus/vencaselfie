from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import uuid
import os
import json
import hashlib
import base64
import random
from datetime import datetime
from upstash_redis import Redis

app = Flask(__name__)
# Enable CORS for your admin.html dashboard
CORS(app)

# --- CONFIGURATION ---
try:
    redis = Redis.from_env()
except Exception as e:
    print(f"Warning: Redis not initialized: {e}")
    redis = None

ADMIN_SECRET_KEY = os.environ.get('ADMIN_SECRET')
# The specific key in Redis storing the dictionary of all valid licenses
REDIS_KEYS_MAP = "vecna_licensed_keys"

def get_fingerprint_hash(fingerprint_data):
    """Creates a consistent SHA-256 hash of the hardware fingerprint."""
    if not fingerprint_data: return None
    canonical_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

def _validate_license_logic(license_key):
    """Checks Upstash Redis for the key and validates expiration."""
    if not license_key or not redis:
        return False, "License key required or DB offline", None
    
    # Retrieve the map of licenses from Redis
    keys_json = redis.get(REDIS_KEYS_MAP)
    allowed_keys = json.loads(keys_json) if keys_json else {}
    
    if license_key not in allowed_keys:
        return False, "Invalid license key.", None
        
    expiry_str = allowed_keys[license_key]
    try:
        expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
        if datetime.now() > expiry_date:
            return False, "License key has expired.", None
        return True, "Valid", expiry_date.timestamp() * 1000
    except Exception:
        return False, "Expiration date error.", None

# --- ADMIN ENDPOINTS ---

@app.route('/api/admin/manage_keys', methods=['POST'])
def manage_keys():
    """Endpoint to ADD or DELETE keys dynamically from the dashboard."""
    try:
        data = request.json or {}
        admin_secret = data.get('admin_secret')
        action = data.get('action') # 'add' or 'delete'
        
        if not ADMIN_SECRET_KEY or admin_secret != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        keys_json = redis.get(REDIS_KEYS_MAP)
        allowed_keys = json.loads(keys_json) if keys_json else {}

        if action == 'add':
            new_key = data.get('license_key')
            expiry = data.get('expiry') # YYYY-MM-DD
            allowed_keys[new_key] = expiry
            msg = f"Key {new_key} added successfully."
        elif action == 'delete':
            target_key = data.get('license_key')
            if target_key in allowed_keys:
                del allowed_keys[target_key]
                # Automatically clean up the hardware lock associated with this key
                redis.delete(f"license_lock:{target_key}")
                msg = f"Key {target_key} and its device lock deleted."
            else:
                return jsonify({"success": False, "message": "Key not found"}), 404
        
        # Save the updated map back to Redis
        redis.set(REDIS_KEYS_MAP, json.dumps(allowed_keys))
        return jsonify({"success": True, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/admin/usage_stats', methods=['POST'])
def get_usage_stats():
    """Fetches keys, total counts, and recent history for the dashboard."""
    try:
        data = request.json or {}
        if not ADMIN_SECRET_KEY or data.get('admin_secret') != ADMIN_SECRET_KEY:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        keys_json = redis.get(REDIS_KEYS_MAP)
        allowed_keys = json.loads(keys_json) if keys_json else {}
        
        stats = {}
        for l_key, expiry in allowed_keys.items():
            count = redis.get(f"usage_count:{l_key}") or 0
            history = redis.lrange(f"usage_history:{l_key}", 0, 9)
            stats[l_key] = {
                "expiry": expiry,
                "total_links": int(count),
                "recent_history": [json.loads(h) for h in history]
            }
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# --- CORE LOGIC ---

@app.route('/api/activate_license', methods=['POST'])
def activate_license():
    """Handles first-time activation and device binding."""
    try:
        raw_data = request.data.decode('utf-8')
        data = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        license_key = data.get('license_key')
        pc_fp = data.get('pc_fingerprint_data')
        
        if not redis: return jsonify({"success": False, "message": "Database Error"}), 500
        
        is_valid, msg, expiry_ms = _validate_license_logic(license_key)
        if not is_valid: return jsonify({"success": False, "message": msg}), 403

        # Device locking mechanism
        incoming_hash = get_fingerprint_hash(pc_fp)
        lock_key = f"license_lock:{license_key}"
        stored_hash = redis.get(lock_key)
        
        if stored_hash and stored_hash != incoming_hash:
            return jsonify({"success": False, "message": "License locked to another device."}), 403
        elif not stored_hash:
            redis.set(lock_key, incoming_hash)

        resp = {"success": True, "activationToken": f"tok_{uuid.uuid4().hex}", "expiryDate": expiry_ms}
        return base64.b64encode(json.dumps(resp).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/create_session', methods=['POST'])
def create_session():
    """Generates the selfie link and tracks usage per key."""
    try:
        raw_data = request.data.decode('utf-8')
        data = json.loads(base64.b64decode(raw_data).decode('utf-8'))
        l_key = data.get('license_key')
        pc_fp = data.get('pc_fingerprint_data')

        is_valid, _, _ = _validate_license_logic(l_key)
        stored_hash = redis.get(f"license_lock:{l_key}")
        if not is_valid or stored_hash != get_fingerprint_hash(pc_fp):
            return jsonify({"success": False, "message": "Unauthorized access denied."}), 403

        # Increment usage count and store history event
        redis.incr(f"usage_count:{l_key}")
        usage_event = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ip": request.remote_addr}
        redis.lpush(f"usage_history:{l_key}", json.dumps(usage_event))
        redis.ltrim(f"usage_history:{l_key}", 0, 49) # Keep last 50 events

        s_id = f"sess_{uuid.uuid4().hex[:16]}"
        s_data = {
            "status": "CREATED", 
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'), 
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
            "server_url": request.host_url.rstrip('/')
        }
        # Session data expires in 24 hours
        redis.set(s_id, json.dumps(s_data), ex=86400)
        
        resp = {"success": True, "session_id": s_id, "client_selfie_link": f"{request.host_url.rstrip('/')}/selfie/?session={s_id}"}
        return base64.b64encode(json.dumps(resp).encode('utf-8')).decode('utf-8')
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# Include other endpoints (update_status.php, submit_liveness.php, etc.) using same Redis pattern

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
