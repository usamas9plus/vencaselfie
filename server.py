from flask import Flask, request, jsonify, send_from_directory
import time
import uuid
import os
import json
from datetime import datetime
import base64
from upstash_redis import Redis # NEW: Import Upstash Redis client

app = Flask(__name__)

# --- REDIS CONFIGURATION ---
try:
    redis = Redis.from_env()
    print("Redis client initialized from environment variables.")
    
    # --- ADD THIS TEST LINE ---
    redis.set("startup_check", int(time.time()))
    print(f"Redis startup check key set successfully: {redis.get('startup_check')}")
    # --- END TEST LINE ---
    
except Exception as e:
    # Fallback/Debug for environments where .from_env() might fail
    print(f"Failed to initialize Redis from environment: {e}. Check UPSTASH_REDIS_REST_URL/TOKEN.")
    redis = None # Set to None if initialization fails
# Redis.from_env() automatically loads UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN 
# from the environment variables, which is ideal for serverless deployment.
try:
    redis = Redis.from_env()
    print("Redis client initialized from environment variables.")
except Exception as e:
    # Fallback/Debug for environments where .from_env() might fail
    print(f"Failed to initialize Redis from environment: {e}. Check UPSTASH_REDIS_REST_URL/TOKEN.")
    redis = None # Set to None if initialization fails

# Session Time-to-Live (TTL) in seconds. Sessions will auto-expire in Redis.
SESSION_TTL_SECONDS = 604800 # 7 days (can be adjusted)

# --- REDIS SESSION HELPERS (REPLACING FILE I/O) ---

def _session_key(session_id):
    """Generates the Redis key for a given session ID."""
    return f"vecna_session:{session_id}"

def get_session_data(session_id):
    """Retrieves session data from Redis."""
    if not redis:
        # Fallback for failed Redis init (should be caught during deployment)
        print("ERROR: Redis client not available.")
        return None
    
    key = _session_key(session_id)
    try:
        # Redis GET command returns the stored JSON string
        session_json = redis.get(key)
        if session_json:
            return json.loads(session_json)
        return None
    except Exception as e:
        print(f"Error retrieving session {session_id} from Redis: {e}")
        return None

def save_session_data(session_id, data):
    """Stores/updates session data in Redis with an expiration."""
    if not redis:
        print("ERROR: Redis client not available.")
        return False
        
    key = _session_key(session_id)
    try:
        session_json = json.dumps(data)
        # SETEX sets the key and the expiration time (TTL) atomically
        redis.setex(key, SESSION_TTL_SECONDS, session_json)
        return True
    except Exception as e:
        print(f"Error saving session {session_id} to Redis: {e}")
        return False
        
def clear_session_data(session_id):
    """Deletes a session from Redis."""
    if not redis:
        print("ERROR: Redis client not available.")
        return False
        
    key = _session_key(session_id)
    try:
        redis.delete(key)
        return True
    except Exception as e:
        print(f"Error clearing session {session_id} from Redis: {e}")
        return False


# --- LICENSE VALIDATION AND FINGERPRINTING (UNCHANGED) ---

def _validate_license_logic(license_key):
    # ... (Keep this function as it was, using os.environ.get('ALLOWED_LICENSE_KEYS', '{}')) ...
    if not license_key:
        return False, "License key is required", None

    # Load keys and dates from Environment Variable
    allowed_keys_env = os.environ.get('ALLOWED_LICENSE_KEYS', '{}')
    
    try:
        allowed_keys_map = json.loads(allowed_keys_env)
    except json.JSONDecodeError:
        print("Error: ALLOWED_LICENSE_KEYS environment variable is not valid JSON.")
        return False, "Server configuration error: License key map invalid", None
        
    if license_key not in allowed_keys_map:
        return False, "Invalid license key", None

    expiry_timestamp_ms = allowed_keys_map.get(license_key)
    
    if expiry_timestamp_ms is None:
        return False, "License expiry data missing", None

    try:
        expiry_ms = int(expiry_timestamp_ms)
    except ValueError:
        return False, "License expiry time is malformed", None
        
    current_time_ms = int(time.time() * 1000)

    if current_time_ms > expiry_ms:
        return False, "License key has expired", expiry_ms

    return True, "License is valid", expiry_ms

# --- API ENDPOINTS (MODIFIED TO USE REDIS HELPERS) ---

@app.route('/api/validate_license.php', methods=['POST'])
def validate_license():
    # ... (Keep existing logic) ...
    try:
        payload = request.json
        license_key = payload.get('license_key')
        fingerprint = payload.get('fingerprint', 'unknown_fp')
        
        is_valid, message, expiry_ms = _validate_license_logic(license_key)
        
        if is_valid:
            # License is valid, now check/update fingerprint history
            key = f"license_fp:{license_key}"
            fp_history = redis.get(key)
            
            if fp_history:
                fp_data = json.loads(fp_history)
                # Check if the fingerprint is already present (or if we need to add a new one)
                if fingerprint not in fp_data.get('fingerprints', []):
                    # For simplicity, let's allow up to 2 unique fingerprints
                    if len(fp_data.get('fingerprints', [])) >= 2:
                        return jsonify({
                            "success": False, 
                            "message": "License limit reached (max 2 unique devices).",
                            "expiry_date": expiry_ms
                        }), 403
                    fp_data['fingerprints'].append(fingerprint)
                
                # Update the last used time
                fp_data['last_used'] = int(time.time() * 1000)
                
                # Save the updated fingerprint data back to Redis with a 30-day expiry
                redis.setex(key, 2592000, json.dumps(fp_data)) # 30 days = 2,592,000 seconds
            else:
                # First time this license is used or history expired
                fp_data = {
                    "license_key": license_key,
                    "fingerprints": [fingerprint],
                    "first_used": int(time.time() * 1000),
                    "last_used": int(time.time() * 1000)
                }
                # Save the new fingerprint data to Redis
                redis.setex(key, 2592000, json.dumps(fp_data)) 

            return jsonify({
                "success": True,
                "message": "License validated successfully.",
                "expiry_date": expiry_ms
            })
        else:
            return jsonify({
                "success": False,
                "message": message,
                "expiry_date": expiry_ms
            }), 401
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {e}"}), 500

@app.route('/api/create_session', methods=['POST'])
def create_session():
    try:
        payload = request.json
        license_key = payload.get('license_key')
        # ... validation logic (optional) ...
        
        # 1. Create a new session ID
        session_id = str(uuid.uuid4())
        
        # 2. Create the session data structure
        new_session = {
            "session_id": session_id,
            "license_key": license_key,
            "status": "WAITING_FOR_CLIENT",
            "polling_count": 0,
            "data": {},
            "created_at": datetime.now().isoformat(),
            # This is the expected ID from the client's injected JS
            "event_session_id": str(uuid.uuid4())
        }
        
        # 3. Save to Redis
        if not save_session_data(session_id, new_session):
             return jsonify({"success": False, "message": "Failed to store session data"}), 500

        # 4. Return success response
        return jsonify({
            "success": True,
            "session_id": session_id,
            "message": "Session created successfully."
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/update_session', methods=['POST'])
def update_session():
    try:
        payload = request.json
        session_id = payload.get('session_id')
        update_data = payload.get('data', {})
        new_status = payload.get('status')
        
        # 1. Retrieve session from Redis
        session = get_session_data(session_id)
        
        if not session:
            return jsonify({"success": False, "message": "Session not found"}), 404
            
        # 2. Apply updates
        if new_status:
            session['status'] = new_status
        if update_data:
            session['data'].update(update_data)
        
        # Increment polling count (optional: to track active duration)
        session['polling_count'] = session.get('polling_count', 0) + 1
        
        # 3. Save updated session back to Redis
        if not save_session_data(session_id, session):
            return jsonify({"success": False, "message": "Failed to update session data"}), 500
        
        # 4. Return success
        return jsonify({"success": True, "message": "Session updated successfully."})
        
    except Exception as e:
        # Note: Added Base64 encoding error handling from your original file for consistency
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/check_session_status', methods=['POST'])
def check_session_status():
    try:
        # Note: Your original function used Base64 decoding/encoding for this route only.
        # It is highly recommended to use standard JSON for all APIs, but maintaining the
        # original flow for compatibility with your existing extension code.
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json # Fallback to standard JSON
            
        session_id = payload.get('session_id')
        
        # 1. Retrieve session from Redis
        session = get_session_data(session_id)
        
        if not session:
            # If session is not found, return an expired/not found status
            response_data = {"success": False, "message": "Session not found/expired"}
        else:
            response_data = {
                "success": True,
                "data": {
                    "status": session['status'],
                    "data": session['data'], # Include full data for client
                    "event_session_id": session['event_session_id']
                }
            }
        
        # 2. Encode and return (to maintain original API contract)
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response
        
    except Exception as e:
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500

@app.route('/api/clear_session', methods=['POST'])
def clear_session():
    try:
        payload = request.json
        session_id = payload.get('session_id')

        # 1. Delete session from Redis
        if not clear_session_data(session_id):
            # Log/handle error, but return success if the goal is just to ensure it's gone
            print(f"Warning: Attempted to clear non-existent or failed-to-delete session {session_id}")
        
        return jsonify({
            "success": True, 
            "message": f"Session {session_id} cleared/deleted."
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# --- Catch-all route to prevent 404s (optional based on your Vercel setup) ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # This route can serve a simple status page or return a 404
    if path.startswith('api/'):
        return jsonify({"message": "API endpoint not found", "path": path}), 404
    return jsonify({"message": "Vecna Serverless API is running"}), 200

if __name__ == '__main__':
    # When running locally, you might want to load environment variables from a .env file
    # and use a local Redis server or the Upstash credentials directly here for testing.
    app.run(debug=True)

