from flask import Flask, request, jsonify, send_from_directory
import time
import uuid
import os
app = Flask(__name__)
app = Flask(__name__)
# Persistence Helper for Vercel (using /tmp)
SESSION_FILE = '/tmp/sessions.json'
def load_sessions():
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}
def save_sessions(sessions_data):
    try:
        with open(SESSION_FILE, 'w') as f:
            json.dump(sessions_data, f)
    except Exception as e:
        print(f"Error saving sessions: {e}")
# Initialize sessions from file
sessions = load_sessions()
@app.route('/')
def index():
    return "Txyber Local Server Running"
@app.route('/selfie/')
def selfie_page():
    # This page exists solely to trigger the Client Extension's background script
    return """
    <html>
    <head><title>Txyber Liveness</title></head>
    <body>
        <h1>Loading Txyber Liveness...</h1>
        <p>Please wait while the secure environment is prepared.</p>
    </body>
    </html>
    """
@app.route('/api/create_session', methods=['POST'])
def create_session():
    try:
        import base64
        import json
        
        # Handle base64 encoded payload (sent by extension for remote servers)
        try:
            raw_data = request.data.decode('utf-8')
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            data = json.loads(decoded_json)
        except:
            data = request.json or {}
        # Admin extension sends: license_key, license_id, tool_identifier, pc_fingerprint_data, selfie_data
        # selfie_data contains: scraped_user_id, scraped_transaction_id, proxy_host_for_client_xff
        
        # We also expect 'server_url' to be passed if we want to construct the link correctly
        server_url = data.get('server_url', request.host_url.rstrip('/'))
        
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        
        sessions[session_id] = {
            "session_id": session_id,
            "status": "CREATED",
            "created_at": time.time(),
            "user_id": data.get('selfie_data', {}).get('scraped_user_id'),
            "transaction_id": data.get('selfie_data', {}).get('scraped_transaction_id'),
            "proxy_host": data.get('selfie_data', {}).get('proxy_host_for_client_xff'),
            "event_session_id": None
        }
        
        # Construct the link that the client will open
        # The Client Extension listens for /selfie/?session=...
        client_link = f"{server_url}/selfie/?session={session_id}"
        
        # Construct response data
        response_data = {
            "success": True,
            "session_id": session_id,
            "client_selfie_link": client_link,
            "message": "Session created successfully"
        }
        
        # Return base64 encoded JSON (as expected by Admin Extension)
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        return b64_response
        
    except Exception as e:
        # Return base64 encoded error so extension can read it
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500
@app.route('/api/get_selfie_data.php', methods=['POST'])
def get_selfie_data():
    try:
        # Client sends base64 encoded payload
        # But for local server, we might receive JSON if we modified the client?
        # The client extension uses 'text/plain' and base64 encoded body.
        # We need to decode it.
        
        import base64
        import json
        
        raw_data = request.data.decode('utf-8')
        try:
            # Try decoding base64
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            # Fallback if sent as raw json
            payload = request.json
            
        session_id = payload.get('session')
        
        if session_id not in sessions:
            return jsonify({
                "success": False, 
                "message": "Session not found"
            })
            
        session = sessions[session_id]
        
        # Return data in the format expected by Client Extension
        response_data = {
            "success": True,
            "data": {
                "user_id": session['user_id'],
                "transaction_id": session['transaction_id'],
                "proxy_host": session['proxy_host'],
                "status": session['status']
            }
        }
        
        # The client expects base64 encoded response?
        # background.js (Client): const decodedResponse = decodePayloadFromBase64BG(responseText);
        # So yes, we must return base64 encoded JSON.
        
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        
        return b64_response
        
    except Exception as e:
        # Return base64 encoded error so extension can read it
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500
@app.route('/api/update_status.php', methods=['POST'])
def update_status():
    try:
        import base64
        import json
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        new_status = payload.get('new_status')
        
        if session_id in sessions:
            sessions[session_id]['status'] = new_status
            print(f"Session {session_id} status updated to {new_status}")
        else:
            # Vercel Workaround: Create skeleton session if missing
            print(f"Session {session_id} not found, creating skeleton for status update.")
            sessions[session_id] = {
                "session_id": session_id,
                "status": new_status,
                "created_at": time.time(),
                "is_skeleton": True
            }
            
        save_sessions(sessions)
        return jsonify({"success": True, "message": "Status updated"})
        
    except Exception as e:
        # Return base64 encoded error so extension can read it
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500
@app.route('/api/submit_liveness.php', methods=['POST'])
def submit_liveness():
    try:
        import base64
        import json
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        event_session_id = payload.get('event_session_id')
        
        if session_id in sessions:
            sessions[session_id]['status'] = 'COMPLETED'
            sessions[session_id]['event_session_id'] = event_session_id
            print(f"Session {session_id} COMPLETED with Event ID: {event_session_id}")
            
        return jsonify({"success": True, "message": "Liveness submitted"})
        
    except Exception as e:
        # Return base64 encoded error so extension can read it
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500
@app.route('/api/check_session_status', methods=['POST'])
def check_session_status():
    try:
        # Admin sends base64 encoded payload
        import base64
        import json
        
        raw_data = request.data.decode('utf-8')
        try:
            decoded_json = base64.b64decode(raw_data).decode('utf-8')
            payload = json.loads(decoded_json)
        except:
            payload = request.json
            
        session_id = payload.get('session_id')
        
        if session_id not in sessions:
            return jsonify({"success": False, "message": "Session not found"})
            
        session = sessions[session_id]
        
        response_data = {
            "success": True,
            "data": {
                "status": session['status'],
                "event_session_id": session['event_session_id']
            }
        }
        
        # Admin expects base64 encoded response
        json_response = json.dumps(response_data)
        b64_response = base64.b64encode(json_response.encode('utf-8')).decode('utf-8')
        
        return b64_response
        
    except Exception as e:
        # Return base64 encoded error so extension can read it
        error_json = json.dumps({"success": False, "message": str(e)})
        b64_error = base64.b64encode(error_json.encode('utf-8')).decode('utf-8')
        return b64_error, 500
if __name__ == '__main__':
    print("Starting Txyber Local Server on port 5000...")
    app.run(host='0.0.0.0', port=5000)
