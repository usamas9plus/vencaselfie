from flask import Flask, request, jsonify
import time
import uuid
import os
import json
from datetime import datetime
from upstash_redis import Redis

app = Flask(__name__)

# --- CONFIGURATION ---
# Initialize Upstash Redis
# Ensure UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are set in Vercel Environment Variables
try:
    redis = Redis.from_env()
except Exception as e:
    print(f"Warning: Redis not initialized. Check Env Vars. Error: {e}")
    redis = None

# License Keys loaded from Env
ALLOWED_LICENSE_KEYS_JSON = os.environ.get('ALLOWED_LICENSE_KEYS', '{}')

def _validate_license_logic(license_key):
    """
    Helper to validate key format, existence, and expiration.
    Returns: (is_valid, error_message, expiry_timestamp_ms)
    """
    if not license_key:
        return False, "License key is required", None

    try:
        allowed_keys_map = json.loads(ALLOWED_LICENSE_KEYS_JSON)
    except json.JSONDecodeError:
        print("Error: ALLOWED_LICENSE_KEYS is not valid JSON")
        allowed_keys_map = {}
    
    # Strict Validation
    if license_key not in allowed_keys_map:
        return False, "Invalid license key.", None
        
    # Check Expiration
    expiry_str = allowed_keys_map[license_key]
    expiry_timestamp_ms = None
    
    try:
        expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d")
        if datetime.now() > expiry_date:
            return False, "License key has expired.", None
        expiry_timestamp_ms = expiry_date.timestamp() * 1000
    except ValueError:
        # Default to 1 year if parsing fails
        expiry_timestamp_ms = (time.time() * 1000) + 31536000000 

    return True, "Valid", expiry_timestamp_ms

# --- ROUTES ---

@app.route('/')
def index():
    return "Vecna Server Running (Upstash Backend). Visit /version to check version."

@app.route('/version')
def version():
    return jsonify({
        "version": "1.1.0", 
        "backend": "upstash-redis",
        "skeleton_support": True,
        "strict_auth": True,
        "expiration_support": True,
        "server_side_check": True,
        "timestamp": time.time()
    })

@app.route('/selfie/')
def selfie_page():
    return """
    <html>
    <head>
        <title>Vecna Selfie - Copy and open this link in Quetta Browser</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&display=swap');
            body { 
                margin: 0; padding: 0; height: 100vh; width: 100vw; overflow: hidden; 
                background: radial-gradient(circle at center, #2b0000 0%, #000000 100%); 
                color: white; font-family: 'Orbitron', sans-serif; 
                display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; 
            }
            h1 { 
                font-size: 2.5em; color: #ff0000; 
                text-shadow: 0 0 10px #ff0000, 0 0 20px #8b0000; 
                margin-bottom: 20px; letter-spacing: 2px; 
            }
            p { 
                color: #e0e0e0; text-shadow: 0 0 2px #ff0000; font-size: 1.2em; 
            }
            a {
                color: #ff0000; text-decoration: none; border-bottom: 1px solid #ff0000; transition: all 0.3s;
            }
            a:hover {
                color: white; text-shadow: 0 0 10px #ff0000;
            }
            .loader { 
                width: 80px; height: 80px; 
                border: 5px solid #8b0000; border-top: 5px solid #ff0000; 
                border-radius: 50%; animation: spin 1s linear infinite; 
                margin-bottom: 30px; box-shadow: 0 0 15px #ff0000; 
            }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            .footer { position: absolute; bottom: 20px; font-size: 0.8em; color: #b0cfe0; opacity: 0.7; }
        </style>
    </head>
    <body>
        <div class="loader"></div>
        <h1>Vecna Selfie</h1>
        <p>Loading...</p>
        <p>لوڈ ہو رہا ہے</p>
        <p>Make sure you have installed Vecna Selfie Extension</p>
        <p>
          <a href="https://bit.ly/VecnaSelfie">Click here to download Vecna Selfie Extension</a>
        </p>
        <div class="footer">Powered by Vecna</div>
    </body>
    </html>
    """

@app.route('/api/activate_license', methods=['POST'])
def activate_license():
    try:
        import base64
        
        try:
            raw_data = request.data.decode('utf-8')
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            data = json.loads(decoded_json)
        except:
            data = request.json or {}
            
        license_key = data.get('license_key')
        
        is_valid, msg, expiry_ms = _validate_license_logic(license_key)
        
        if not is_valid:
             return jsonify({"success": False, "message": msg}), 403

        activation_token = f"tok_{uuid.uuid4().hex}"
        
        response_data = {
            "success": True,
            "activationToken": activation_token,
            "licenseId": 1001,
            "status": "valid",
            "expiryDate": expiry_ms, 
            "message": "License activated successfully"
        }
        
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response

    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/create_session', methods=['POST'])
def create_session():
    try:
        import base64
        
        try:
            raw_data = request.data.decode('utf-8')
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            data = json.loads(decoded_json)
        except:
            data = request.json or {}
        
        # Security Check
        license_key = data.get('license_key')
        is_valid, msg, _ = _validate_license_logic(license_key)
        
        if not is_valid:
            print(f"Blocked session creation attempt with invalid key: {license_key}")
            return jsonify({"success": False, "message": f"Security Check Failed: {msg}"}), 403
        
        server_url = data.get('server_url', request.host_url.rstrip('/'))
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        
        # Session Object
        new_session = {
            "session_id": session_id,
            "status": "CREATED",
            "created_at": time.time(),
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'),
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy_host": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
            "event_session_id": None,
            "server_url": server_url
        }
        
        # Save to Redis (Expire in 24h = 86400s)
        if redis:
            redis.set(session_id, json.dumps(new_session), ex=86400)
        
        client_link = f"{server_url}/selfie/?session={session_id}"
        
        response_data = {
            "success": True,
            "session_id": session_id,
            "client_selfie_link": client_link,
            "message": "Session created successfully"
        }
        
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/get_selfie_data.php', methods=['POST'])
def get_selfie_data():
    try:
        import base64
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session')
        
        # Fetch from Redis
        session_data_str = redis.get(session_id) if redis else None
        
        if not session_data_str:
            return jsonify({"success": False, "message": "Session not found or expired"})
            
        session = json.loads(session_data_str)
        
        response_data = {
            "success": True,
            "data": {
                "user_id": session.get('user_id'),
                "transaction_id": session.get('transaction_id'),
                "proxy_host": session.get('proxy_host'),
                "status": session.get('status'),
                "server_url": session.get('server_url', request.host_url.rstrip('/'))
            }
        }
        
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/update_status.php', methods=['POST'])
def update_status():
    try:
        import base64
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        new_status = payload.get('new_status')
        
        # Retrieve existing session
        session_data_str = redis.get(session_id) if redis else None
        
        if session_data_str:
            session = json.loads(session_data_str)
            session['status'] = new_status
        else:
            # Fallback for skeleton sessions (rare case if created directly via update)
            session = {
                "session_id": session_id,
                "status": new_status,
                "created_at": time.time(),
                "is_skeleton": True
            }

        # Save back to Redis
        if redis:
            redis.set(session_id, json.dumps(session), ex=86400)

        return jsonify({"success": True, "message": "Status updated"})
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/submit_liveness.php', methods=['POST'])
def submit_liveness():
    try:
        import base64
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        event_session_id = payload.get('event_session_id')
        
        session_data_str = redis.get(session_id) if redis else None
        
        if session_data_str:
            session = json.loads(session_data_str)
            session['status'] = 'COMPLETED'
            session['event_session_id'] = event_session_id
        else:
            session = {
                "session_id": session_id,
                "status": 'COMPLETED',
                "event_session_id": event_session_id,
                "created_at": time.time(),
                "is_skeleton": True
            }
            
        if redis:
            redis.set(session_id, json.dumps(session), ex=86400)
            
        return jsonify({"success": True, "message": "Liveness submitted"})
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/check_session_status', methods=['POST'])
def check_session_status():
    try:
        import base64
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        
        session_data_str = redis.get(session_id) if redis else None
        
        if not session_data_str:
            return jsonify({"success": False, "message": "Session not found"})
            
        session = json.loads(session_data_str)
        
        response_data = {
            "success": True,
            "data": {
                "status": session.get('status'),
                "event_session_id": session.get('event_session_id')
            }
        }
        
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
