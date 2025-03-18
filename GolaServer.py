import os
import json
from datetime import datetime
import requests
import logging
import hashlib
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, ImageDraw
import io
import base64
import numpy as np
import matplotlib.pyplot as plt
import torch
from torchvision import models, transforms
from marshmallow import Schema, fields, ValidationError, validates_schema

app = Flask(__name__)

# --- Configuration ---
IMAGERY_SERVER_PORT = int(os.environ.get('IMAGERY_SERVER_PORT', 5001))
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
IMAGERY_DIR = os.environ.get('IMAGERY_DIR', 'imagery') 
SENTINEL_API_KEY = os.environ.get('SENTINEL_API_KEY', None)
FLASK_SERVER_URL = os.environ.get('FLASK_SERVER_URL', 'http://localhost:5000')
API_TOKEN = os.environ.get('API_TOKEN', 'your_jwt_token') 
CA_CERT_PATH = os.environ.get('CA_CERT_PATH', 'certs/ca.crt')
WHITELISTED_IPS = os.environ.get('WHITELISTED_IPS', '127.0.0.1').split(',') 

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - IP: %(ip)s - User: %(user)s',
    handlers=[logging.FileHandler('imagery_server.log'), logging.StreamHandler()]
)

class ContextFilter(logging.Filter):
    def filter(self, record):
        try:
            record.ip = request.remote_addr or 'N/A'
            record.user = request.headers.get('X-User', 'anonymous')
        except RuntimeError:
            record.ip = 'N/A'
            record.user = 'anonymous'
        return True
    
logging.getLogger().addFilter(ContextFilter())

# --- Security Setup ---
cipher = Fernet(ENCRYPTION_KEY.encode())
limiter = Limiter(get_remote_address, app=app, default_limits=["50 per day", "5 per minute"])

def verify_api_token(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            logging.warning(f"Missing or invalid token from {request.remote_addr}")
            return jsonify({"status": "error", "message": "Token required"}), 401
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

def csrf_protect(f):
    def decorator(*args, **kwargs):
        if request.method in ['POST']:
            csrf_token = request.headers.get('X-CSRF-Token')
            if not csrf_token or not requests.get(
                f"{FLASK_SERVER_URL}/csrf-token",
                headers={'Authorization': f'Bearer {API_TOKEN}'},
                timeout=5
            ).json().get('csrf_token') == csrf_token:
                logging.warning(f"Invalid CSRF token from {request.remote_addr}")
                return jsonify({"status": "error", "message": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

def restrict_ip(f):
    def decorator(*args, **kwargs):
        client_ip = request.remote_addr
        if client_ip not in WHITELISTED_IPS:
            logging.warning(f"Unauthorized IP access attempt: {client_ip}")
            return jsonify({"status": "error", "message": "IP not whitelisted"}), 403
        return f(*args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# --- Imagery Processor ---
class SatelliteImageryProcessor:
    def __init__(self):
        self.storage_dir = IMAGERY_DIR
        self.model = models.detection.fasterrcnn_resnet50_fpn(pretrained=True)
        self.model.eval()
        self.transform = transforms.Compose([transforms.ToTensor()])

    def fetch_imagery(self, bbox: dict) -> bytes:
        url = "https://services.sentinel-hub.com/ogc/wms/YOUR_INSTANCE_ID"
        params = {
            'service': 'WMS', 'request': 'GetMap', 'layers': 'TRUE_COLOR',
            'bbox': f"{bbox['west']},{bbox['south']},{bbox['east']},{bbox['north']}",
            'width': 600, 'height': 400, 'format': 'image/png'
        }
        response = requests.get(url, params=params, headers={'Authorization': f'Bearer {SENTINEL_API_KEY}'}, timeout=10, verify=CA_CERT_PATH)
        response.raise_for_status()
        return response.content

    def fetch_osint_data(self, job_id: str = None) -> dict:
        headers = {'Authorization': f'Bearer {API_TOKEN}'}
        if job_id:
            try:
                response = requests.get(f"{FLASK_SERVER_URL}/api/jobs/{job_id}", headers=headers, timeout=5)
                if response.status_code == 200:
                    job_data = response.json().get('job', {})
                    results = job_data.get('results', {})
                    locations = results.get('locations', []) or [{'lat': results.get('lat'), 'lon': results.get('lon')}] if 'lat' in results else []
                    return {
                        'locations': locations,
                        'details': results.get('details', 'No details')
                    }
            except requests.RequestException as e:
                logging.error(f"Failed to fetch OSINT data: {str(e)}")
        return {'locations': [], 'details': 'No OSINT data'}

    def process_osint_density(self, osint_data: list) -> dict:
        lats = [float(d['lat']) for d in osint_data if d.get('lat') and d.get('lon') and isinstance(d['lat'], (int, float))]
        lons = [float(d['lon']) for d in osint_data if d.get('lat') and d.get('lon') and isinstance(d['lon'], (int, float))]
        if not lats or not lons:
            img = Image.new('RGBA', (600, 400), (0, 0, 0, 0))
            return {'overlay': img, 'density_points': []}
        plt.figure(figsize=(6, 4))
        plt.hist2d(lons, lats, bins=50, cmap='hot')
        plt.axis('off')
        buf = io.BytesIO()
        plt.savefig(buf, format='png', transparent=True, bbox_inches='tight', pad_inches=0)
        plt.close()
        buf.seek(0)
        overlay = Image.open(buf).convert('RGBA')
        density_points = [{'lat': lat, 'lon': lon} for lat, lon in zip(lats, lons)]
        return {'overlay': overlay, 'density_points': density_points}

    def process_osint_location(self, lat: float, lon: float, details: str = None) -> dict:
        img = Image.new('RGBA', (600, 400), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        x, y = 300, 200
        draw.ellipse([x-10, y-10, x+10, y+10], fill='red', outline='black')
        if details:
            sanitized_details = ''.join(c for c in details if c.isalnum() or c.isspace())[:50]
            draw.text((x+15, y-10), sanitized_details, fill='white')
        return {'overlay': img, 'location': {'lat': lat, 'lon': lon, 'details': sanitized_details}}

    def process_object_detection(self, raw_imagery: bytes) -> dict:
        img = Image.open(io.BytesIO(raw_imagery)).convert('RGB')
        tensor = self.transform(img).unsqueeze(0)
        with torch.no_grad():
            predictions = self.model(tensor)[0]
        draw = ImageDraw.Draw(img)
        detected_objects = []
        for box, label, score in zip(predictions['boxes'], predictions['labels'], predictions['scores']):
            if score > 0.5 and label == 1:
                x0, y0, x1, y1 = box.tolist()
                draw.rectangle([x0, y0, x1, y1], outline='green', width=2)
                draw.text((x0, y0-10), f"Person ({score:.2f})", fill='green')
                detected_objects.append({'type': 'person', 'bbox': [x0, y0, x1, y1], 'confidence': score.item()})
        return {'overlay': img.convert('RGBA'), 'objects': detected_objects}

    def overlay_on_imagery(self, raw_imagery: bytes, overlay: Image) -> bytes:
        base = Image.open(io.BytesIO(raw_imagery)).convert('RGBA')
        combined = Image.alpha_composite(base, overlay.resize(base.size))
        output = io.BytesIO()
        combined.save(output, format='PNG')
        return output.getvalue()

    def store_imagery(self, imagery_data: bytes, filename: str) -> str:
        encrypted_data = cipher.encrypt(imagery_data)
        hash_value = hashlib.sha256(imagery_data).hexdigest()
        sanitized_filename = ''.join(c for c in filename if c.isalnum() or c in ['-', '_', '.'])
        os.makedirs(self.storage_dir, exist_ok=True)
        filepath = os.path.join(self.storage_dir, sanitized_filename)
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        with open(os.path.join(self.storage_dir, 'hash_store.txt'), 'a') as f:
            f.write(f"{sanitized_filename}:{hash_value}\n")
        return filepath

    def retrieve_imagery(self, filename: str) -> bytes:
        sanitized_filename = ''.join(c for c in filename if c.isalnum() or c in ['-', '_', '.'])
        filepath = os.path.join(self.storage_dir, sanitized_filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError("Imagery not found")
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        stored_hash = None
        hash_file = os.path.join(self.storage_dir, 'hash_store.txt')
        if os.path.exists(hash_file):
            with open(hash_file, 'r') as f:
                for line in f:
                    if line.startswith(sanitized_filename):
                        stored_hash = line.split(':')[1].strip()
        if stored_hash and hashlib.sha256(decrypted_data).hexdigest() != stored_hash:
            logging.error(f"Integrity check failed for {sanitized_filename}")
            raise Exception("Imagery integrity check failed")
        return decrypted_data

processor = SatelliteImageryProcessor()

# --- Schemas ---
class ImageryRequestSchema(Schema):
    bbox = fields.Dict(required=True, keys=fields.Str(), values=fields.Float())
    analysis_type = fields.Str(missing='density', validate=lambda x: x in ['density', 'location', 'object_detection'])
    lat = fields.Float(missing=None)
    lon = fields.Float(missing=None)
    job_id = fields.Str(missing=None)

    @validates_schema
    def validate_bbox(self, data, **kwargs):
        bbox = data['bbox']
        for key in ['west', 'south', 'east', 'north']:
            if key not in bbox or not isinstance(bbox[key], (int, float)):
                raise ValidationError(f"Invalid bbox: {key} must be a number")
        width = bbox['east'] - bbox['west']
        height = bbox['north'] - bbox['south']
        if width > 1 or height > 1:
            raise ValidationError("Bounding box too large")

# --- API Endpoints ---
@app.route('/api/imagery', methods=['POST'])
@verify_api_token
@csrf_protect
@restrict_ip
@limiter.limit("3 per minute;10 per hour")
def process_imagery():
    try:
        data = ImageryRequestSchema().load(request.get_json())
        bbox = data['bbox']
        analysis_type = data['analysis_type']
        job_id = data.get('job_id')

        osint_data = processor.fetch_osint_data(job_id)
        raw_imagery = processor.fetch_imagery(bbox)

        if analysis_type == 'density':
            result = processor.process_osint_density(osint_data.get('locations', []))
        elif analysis_type == 'location':
            if not data['lat'] or not data['lon']:
                return jsonify({"status": "error", "message": "lat and lon required"}), 400
            details = osint_data.get('details', 'Target')
            result = processor.process_osint_location(data['lat'], data['lon'], details)
        elif analysis_type == 'object_detection':
            result = processor.process_object_detection(raw_imagery)
        else:
            return jsonify({"status": "error", "message": "Invalid analysis type"}), 400

        processed_imagery = processor.overlay_on_imagery(raw_imagery, result['overlay'])
        filename = f"imagery_{analysis_type}_{datetime.utcnow().isoformat()}.png"
        imagery_path = processor.store_imagery(processed_imagery, filename)
        image_b64 = base64.b64encode(processed_imagery).decode('utf-8')

        response_data = {
            "status": "success",
            "imagery": {"path": imagery_path, "base64": image_b64},
            "osint": result.get('density_points') or result.get('location') or result.get('objects'),
            "timestamp": datetime.utcnow().isoformat()
        }

        logging.info(f"Imagery processed: {analysis_type} for bbox {bbox}")
        return jsonify(response_data), 200
    except ValidationError as e:
        logging.warning(f"Validation error: {str(e.messages)}")
        return jsonify({"status": "error", "message": str(e.messages)}), 400
    except Exception as e:
        logging.error(f"Imagery processing failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/imagery/<filename>', methods=['GET'])
@verify_api_token
@restrict_ip
@limiter.limit("5 per minute")
def get_imagery(filename):
    try:
        decrypted_data = processor.retrieve_imagery(filename)
        image_b64 = base64.b64encode(decrypted_data).decode('utf-8')
        response_data = {
            "status": "success",
            "imagery": {"base64": image_b64},
            "timestamp": datetime.utcnow().isoformat()
        }
        logging.info(f"Imagery retrieved: {filename}")
        return jsonify(response_data), 200
    except Exception as e:
        logging.error(f"Imagery retrieval failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 404

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    required_vars = ['ENCRYPTION_KEY', 'SENTINEL_API_KEY', 'API_TOKEN', 'CA_CERT_PATH']
    for var in required_vars:
        if not os.environ.get(var):
            logging.error(f"Missing required env var: {var}")
            exit(1)
    
    ssl_context = ('certs/server.crt', 'certs/server.key') if os.environ.get('FLASK_ENV') != 'development' else 'adhoc'
    app.run(host='0.0.0.0', port=IMAGERY_SERVER_PORT, debug=False, ssl_context=ssl_context)