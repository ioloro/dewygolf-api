from flask import Flask, request, jsonify, g, redirect, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import sqlite3
import math
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from urllib.parse import urlparse, parse_qs
import re
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import hmac
import base64
import ssl
import certifi

# ============================================================================
# APP CONFIGURATION AND ENVIRONMENT VARIABLES
# ============================================================================

app = Flask(__name__)

CORS_ORIGINS = os.environ.get('CORS_ORIGINS')
DATABASE_URL = os.environ.get('DATABASE_URL')
EXPECTED_SSL_FINGERPRINTS = os.environ.get('EXPECTED_SSL_FINGERPRINTS', '').split(',') if os.environ.get('EXPECTED_SSL_FINGERPRINTS') else []
HONEYPOT_ENABLED = os.environ.get('HONEYPOT_ENABLED', 'true').lower() == 'true'
MAX_REQUESTS_PER_API_KEY = int(os.environ.get('MAX_REQUESTS_PER_API_KEY', 10))
RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
SSL_PINNING_ENABLED = os.environ.get('SSL_PINNING_ENABLED', 'true').lower() == 'true'
API_KEYS = os.environ.get('WHITELISTED_API_KEYS', [])

app.logger.info(f'DATABASE_URL: {DATABASE_URL}; RATE_LIMIT_ENABLED {RATE_LIMIT_ENABLED}; SSL_PINNING_ENABLED {SSL_PINNING_ENABLED}; EXPECTED_SSL_FINGERPRINTS {EXPECTED_SSL_FINGERPRINTS}; MAX_REQUESTS_PER_API_KEY {MAX_REQUESTS_PER_API_KEY}; HONEYPOT_ENABLED {HONEYPOT_ENABLED}')
DATABASE = DATABASE_URL

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["60 per hour", "10 per minute"] if RATE_LIMIT_ENABLED else [],
    storage_uri=os.environ.get('RATE_LIMIT_STORAGE_URI', 'memory://'),
    strategy='fixed-window'
)

cors = CORS(app, 
    origins=CORS_ORIGINS,
    methods=['GET', 'POST'],
    allow_headers=['Content-Type', 'X-API-Key'],
    max_age=3600
)

# ============================================================================
# SSL PINNING AND CERTIFICATE VERIFICATION
# ============================================================================

def get_ssl_fingerprint(peer_cert):
    """Extract SHA256 fingerprint from SSL certificate."""
    try:
        der_cert = ssl.DER_cert_to_PEM_cert(peer_cert)
        # Convert PEM to DER for hashing
        cert_bytes = ssl.PEM_cert_to_DER_cert(der_cert)
        fingerprint = hashlib.sha256(cert_bytes).hexdigest()
        return fingerprint.upper()
    except Exception as e:
        app.logger.error(f'Error extracting SSL fingerprint: {str(e)}')
        return None

def verify_ssl_pinning():
    """Verify SSL certificate pinning for incoming requests."""
    if not SSL_PINNING_ENABLED:
        return True
    
    try:
        # Get client certificate if provided
        peer_cert = request.environ.get('SSL_CLIENT_CERT')
        if not peer_cert:
            # No client cert provided, check if required
            if EXPECTED_SSL_FINGERPRINTS:
                log_security_event('SSL_PINNING_FAILED', 'No client certificate provided')
                return False
            return True
        
        fingerprint = get_ssl_fingerprint(peer_cert)
        if not fingerprint:
            log_security_event('SSL_PINNING_FAILED', 'Could not extract certificate fingerprint')
            return False
        
        # Check against expected fingerprints
        if EXPECTED_SSL_FINGERPRINTS:
            if fingerprint not in EXPECTED_SSL_FINGERPRINTS:
                log_security_event('SSL_PINNING_FAILED', f'Certificate fingerprint mismatch: {fingerprint}')
                return False
        
        return True
    except Exception as e:
        log_security_event('SSL_PINNING_ERROR', f'SSL verification error: {str(e)}')
        return False

# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    
    # Remove server information
    response.headers.pop('Server', None)
    
    return response


# ============================================================================
# ENHANCED LOGGING
# ============================================================================

def log_security_event(event_type, details):
    """Log security-related events with enhanced details."""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'details': details,
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'path': request.path,
        'method': request.method,
        'api_key_hash': hash_api_key(g.apiKey)[:16] if hasattr(g, 'apiKey') else None
    }
    
    app.logger.warning(f'SECURITY_EVENT: {log_entry}')

# Configure logging
def setup_logging():
    """Configure application logging with both file and console handlers."""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # Set up file handler with rotation
    file_handler = RotatingFileHandler(
        'logs/golfcourse_api.log',
        maxBytes=10240000,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    
    # Set up console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    console_handler.setLevel(logging.INFO)
    
    # Security events handler (separate file)
    security_handler = RotatingFileHandler(
        'logs/security.log',
        maxBytes=10240000,
        backupCount=10
    )
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s SECURITY: %(message)s'
    ))
    security_handler.setLevel(logging.WARNING)
    
    # Configure app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.addHandler(security_handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info('Logging configured successfully')

# Initialize logging
setup_logging()


# ============================================================================
# API KEY VERIFICATION AND USER MANAGEMENT
# ============================================================================

def generate_api_key():
    """Generate a secure random API key."""
    return secrets.token_urlsafe(32)

def hash_api_key(apiKey):
    """Hash API key for secure storage comparison."""
    return hashlib.sha256(apiKey.encode()).hexdigest()

def verify_api_key_rate_limit(apiKey):
    """Check if API key has exceeded its rate limit."""
    try:
        users_db = get_db()
        
        result = users_db.run(
            'SELECT request_count, last_reset FROM users WHERE apiKey = :apiKey',
            apiKey=apiKey
        )
        user_data = result[0] if result else None
        
        if not user_data:
            return True
        
        request_count = user_data[0] if isinstance(user_data, (tuple, list)) else user_data['request_count']
        last_reset = user_data[1] if isinstance(user_data, (tuple, list)) else user_data['last_reset']
        
        # Parse last reset time
        if isinstance(last_reset, str):
            last_reset = datetime.fromisoformat(last_reset)
        
        # Reset counter if more than 24 hours have passed
        if datetime.utcnow() - last_reset > timedelta(hours=24):
            users_db.run(
                'UPDATE users SET request_count = 0, last_reset = :now WHERE apiKey = :apiKey',
                now=datetime.utcnow(),
                apiKey=apiKey
            )
            return True
        
        # Check if limit exceeded
        if request_count >= MAX_REQUESTS_PER_API_KEY:
            return False
        
        return True
    except Exception as e:
        app.logger.error(f'Error checking API key rate limit: {str(e)}')
        return True  # Fail open on error

def increment_api_key_usage(apiKey):
    """Increment the request count for an API key."""
    try:
        users_db = get_db()

        users_db.run(
            '''UPDATE users 
               SET request_count = request_count + 1, 
                   last_used_at = :now 
               WHERE apiKey = :apiKey''',
            now=datetime.utcnow(),
            apiKey=apiKey
        )
    except Exception as e:
        app.logger.error(f'Error incrementing API key usage: {str(e)}')

def require_api_key(f):
    """Enhanced decorator to require API key authentication with comprehensive checks."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # SSL Pinning Check
        if not verify_ssl_pinning():
            log_security_event('SSL_PINNING_VIOLATION', 'Request failed SSL pinning check')
            return jsonify({'error': 'SSL verification failed'}), 403
        
        # Extract API key
        apiKey = request.headers.get('X-API-Key') or request.args.get('apiKey')
        
        if not apiKey:
            log_security_event('MISSING_API_KEY', 'Request without API key')
            return jsonify({'error': 'API key required', 'hint': 'Include X-API-Key header or apiKey parameter'}), 401
        
        # Validate API key format
        if not re.match(r'^[A-Za-z0-9_-]{32,}$', apiKey):
            log_security_event('INVALID_API_KEY_FORMAT', f'Malformed API key from {request.remote_addr}')
            return jsonify({'error': 'Invalid API key format'}), 401
        
        # Check if users database is available
        # if not users_db_available:
        #     app.logger.warning('Users database unavailable - falling back to config check')
        #     if apiKey not in API_KEYS:
        #         log_security_event('INVALID_API_KEY', f'Invalid API key attempt from {request.remote_addr}')
        #         return jsonify({'error': 'Invalid API key'}), 401
        #     return f(*args, **kwargs)
        
        try:
            users_db = get_db()
            
            # Check if API key exists in database
            result = users_db.run(
                'SELECT apiKey, is_banned, is_active, request_count FROM users WHERE apiKey = :apiKey',
                apiKey=apiKey
            )
            user = result[0] if result else None

            if user:
                # Extract user data
                is_banned = user[1] if isinstance(user, (tuple, list)) else user['is_banned']
                is_active = user[2] if isinstance(user, (tuple, list)) else user['is_active']
                
                # Check if user is banned
                if is_banned:
                    log_security_event('BANNED_API_KEY', f'Banned API key attempt from {request.remote_addr}')
                    return jsonify({'error': 'API key has been banned', 'reason': 'Terms of service violation'}), 403
                
                # Check if user is active
                if not is_active:
                    log_security_event('INACTIVE_API_KEY', f'Inactive API key attempt from {request.remote_addr}')
                    return jsonify({'error': 'API key is inactive', 'hint': 'Contact support to reactivate'}), 403
                
                # Check per-key rate limit
                if not verify_api_key_rate_limit(apiKey):
                    log_security_event('API_KEY_RATE_LIMIT', f'API key {apiKey[:8]}... exceeded rate limit')
                    return jsonify({
                        'error': 'API key rate limit exceeded',
                        'limit': MAX_REQUESTS_PER_API_KEY,
                        'reset_in': '24 hours'
                    }), 429
                
                # Increment usage counter
                increment_api_key_usage(apiKey)
                
                # Store API key in g for use in endpoint
                g.apiKey = apiKey
                
                app.logger.info(f'Valid API key access from {request.remote_addr}')
                return f(*args, **kwargs)
            else:
                # API key doesn't exist - create new user
                app.logger.info(f'New API key detected from {request.remote_addr}, creating user account')
                
                users_db.run(
                    '''INSERT INTO users (apiKey, is_banned, is_active, created_at, last_used_at, request_count, last_reset) 
                       VALUES (:apiKey, :is_banned, :is_active, :created_at, :last_used_at, :request_count, :last_reset)''',
                    apiKey=apiKey,
                    is_banned=False,
                    is_active=True,
                    created_at=datetime.utcnow(),
                    last_used_at=datetime.utcnow(),
                    request_count=1,
                    last_reset=datetime.utcnow()
                )

                # Store API key in g
                g.apiKey = apiKey
                
                app.logger.info('Successfully created new user account')
                return f(*args, **kwargs)
                
        except Exception as e:
            app.logger.error(f'Error checking API key in database: {str(e)}', exc_info=True)
            log_security_event('API_KEY_CHECK_ERROR', f'Database error: {str(e)}')
            return jsonify({'error': 'Internal server error during authentication'}), 500
        
    return decorated_function


# ============================================================================
# INPUT VALIDATION
# ============================================================================

def validate_coordinates(lat, lng):
    """Validate latitude and longitude values."""
    try:
        lat = float(lat)
        lng = float(lng)
        
        if not (-90 <= lat <= 90):
            raise ValueError('Latitude must be between -90 and 90')
        if not (-180 <= lng <= 180):
            raise ValueError('Longitude must be between -180 and 180')
        
        return lat, lng
    except (ValueError, TypeError) as e:
        raise ValueError(f'Invalid coordinates: {str(e)}')

def sanitize_input(text):
    """Sanitize user input to prevent injection attacks."""
    if not isinstance(text, str):
        return text
    
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\'&;]', '', text)
    # Remove SQL keywords (case insensitive)
    sql_keywords = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'EXEC', 'UNION', 'SELECT']
    for keyword in sql_keywords:
        text = re.sub(rf'\b{keyword}\b', '', text, flags=re.IGNORECASE)
    # Limit length
    text = text[:100]
    return text.strip()

def validate_search_params(data):
    """Validate and sanitize search parameters."""
    validated = {}
    
    # Validate limit
    limit = data.get('limit', 10)
    try:
        limit = int(limit)
        if limit < 1 or limit > 100:
            limit = 10
    except (ValueError, TypeError):
        limit = 10
    validated['limit'] = limit
    
    # Validate and sanitize text inputs
    for field in ['city', 'zipcode', 'name']:
        if field in data:
            validated[field] = sanitize_input(data[field])
    
    # Validate coordinates
    if 'lat' in data and 'lng' in data:
        try:
            validated['lat'], validated['lng'] = validate_coordinates(data['lat'], data['lng'])
        except ValueError as e:
            raise ValueError(str(e))
    
    return validated

# ============================================================================
# ANTI-SCRAPING MEASURES
# ============================================================================

def detect_bot_behavior():
    """Detect potential bot/scraper behavior."""
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Common bot indicators
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 
        'python-requests', 'http', 'scrapy', 'selenium', 'phantomjs'
    ]
    
    # Check if user agent contains bot indicators
    if any(indicator in user_agent for indicator in bot_indicators):
        return True
    
    # Check for missing or suspicious user agent
    if not user_agent or len(user_agent) < 10:
        return True
    
    # Check request frequency (stored in g)
    if hasattr(g, 'request_count'):
        if g.request_count > 100:  # More than 100 requests in session
            return True
    
    return False

def check_request_patterns():
    """Analyze request patterns for suspicious activity."""
    suspicious = False
    reasons = []
    
    # Check for rapid sequential requests
    if hasattr(g, 'last_request_time'):
        time_diff = (datetime.utcnow() - g.last_request_time).total_seconds()
        if time_diff < 0.5:  # Less than 500ms between requests
            suspicious = True
            reasons.append('rapid_requests')
    
    # Check for parameter manipulation attempts
    if request.args:
        for key, value in request.args.items():
            # Check for SQL injection attempts
            if any(keyword in str(value).upper() for keyword in ['UNION', 'SELECT', 'DROP', 'DELETE']):
                suspicious = True
                reasons.append('sql_injection_attempt')
            # Check for XSS attempts
            if any(char in str(value) for char in ['<', '>', 'script']):
                suspicious = True
                reasons.append('xss_attempt')
    
    g.last_request_time = datetime.utcnow()
    
    return suspicious, reasons

@app.before_request
def check_security():
    """Pre-request security checks."""
    # Bot detection
    if detect_bot_behavior():
        log_security_event('BOT_DETECTED', f'Potential bot detected: {request.headers.get("User-Agent")}')
        # Don't block immediately, but log and monitor
    
    # Check request patterns
    suspicious, reasons = check_request_patterns()
    if suspicious:
        log_security_event('SUSPICIOUS_PATTERN', f'Suspicious activity: {", ".join(reasons)}')
        # Could implement blocking here if needed

# ============================================================================
# HONEYPOT ENDPOINT (Trap for scrapers)
# ============================================================================

@app.route("/admin")
@app.route("/config")
@app.route("/backup")
@app.route("/.env")
@app.route("/database")
def honeypot():
    """Honeypot endpoint to catch scrapers."""
    if HONEYPOT_ENABLED:
        log_security_event('HONEYPOT_TRIGGERED', f'Suspicious access to honeypot endpoint: {request.path}')
        
        # Ban the API key if present
        apiKey = request.headers.get('X-API-Key') or request.args.get('apiKey')
        if apiKey and users_db_available:
            try:
                users_db = get_db()
                users_db.run(
                    'UPDATE users SET is_banned = :banned WHERE apiKey = :apiKey',
                    banned=True,
                    apiKey=apiKey
                )
                app.logger.warning(f'API key banned after honeypot trigger: {apiKey[:8]}...')
            except Exception as e:
                app.logger.error(f'Error banning API key: {str(e)}')
    
    abort(404)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_distance(lat1, lng1, lat2, lng2):
    """Calculate distance between two coordinates using Haversine formula."""
    R = 3959  # Earth's radius in miles
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lng = math.radians(lng2 - lng1)
    
    a = math.sin(delta_lat/2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lng/2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c

def get_row_value(row, index):
    """Get value from row regardless of database type."""
    if isinstance(row, dict):
        keys = list(row.keys())
        return row[keys[index]]
    return row[index]

def course_to_dict(row):
    """Convert database row to dictionary."""
    if isinstance(row, dict):
        return dict(row)
    
    # SQLite row
    return {
        'id': row[0],
        'name': row[1],
        'address': row[2],
        'city': row[3],
        'zipcode': row[4],
        'website': row[5],
        'phone': row[6],
        'holes': row[7],
        'lat': row[8],
        'lng': row[9]
    }

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route("/")
@limiter.limit("2 per minute")
def root_route():
    return redirect("https://www.dewygolf.com", code=302)

@app.route("/search", methods=['GET', 'POST'])
@require_api_key
@limiter.limit("5 per minute")
def search():
    """Search for golf courses with enhanced security."""
    try:
        # Get request data
        if request.method == 'POST':
            data = request.get_json() or {}
        else:
            data = request.args.to_dict()
        
        app.logger.info(f'Search request received with data: {data}')
        
        # Validate and sanitize input
        try:
            validated_data = validate_search_params(data)
        except ValueError as e:
            log_security_event('VALIDATION_ERROR', str(e))
            return jsonify({'success': False, 'error': str(e)}), 400
        
        db = get_db()
        
        lat = validated_data.get('lat')
        lng = validated_data.get('lng')
        city = validated_data.get('city')
        zipcode = validated_data.get('zipcode')
        name = validated_data.get('name')
        limit = validated_data.get('limit', 10)
        
        # Location-based search
        if lat is not None and lng is not None:
            app.logger.info(f'Performing location-based search at ({lat}, {lng})')
            
            cursor = db.cursor()
            cursor.execute('SELECT * FROM golfcourse')
            all_courses = cursor.fetchall()
            
            # Calculate distances
            courses_with_distance = []
            for course in all_courses:
                course_lat = get_row_value(course, 8)
                course_lng = get_row_value(course, 9)
                
                if course_lat and course_lng:
                    try:
                        distance = calculate_distance(lat, lng, float(course_lat), float(course_lng))
                        course_dict = course_to_dict(course)
                        course_dict['distance'] = round(distance, 2)
                        courses_with_distance.append(course_dict)
                    except (ValueError, TypeError):
                        continue
            
            # Sort by distance and limit
            courses_with_distance.sort(key=lambda x: x['distance'])
            results = courses_with_distance[:limit]
            
            app.logger.info(f'Location search completed - Found {len(results)} courses')
            
            return jsonify({
                'success': True,
                'search_type': 'location',
                'coordinates': {'lat': lat, 'lng': lng},
                'results': results,
                'total_found': len(results)
            })
        
        # City-based search
        elif city:
            app.logger.info(f'Performing city-based search for: {city}')
            
            cursor = db.cursor()
            cursor.execute(
                'SELECT * FROM golfcourse WHERE LOWER(city) LIKE LOWER(%s) LIMIT %s',
                (f'%{city}%', limit)
            )
            results = cursor.fetchall()

            app.logger.info(f'City search completed - Found {len(results)} courses')
            
            return jsonify({
                'success': True,
                'search_type': 'city',
                'search_term': city,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        # Zipcode-based search
        elif zipcode:
            app.logger.info(f'Performing zipcode-based search for: {zipcode}')
            
            cursor = db.cursor()
            cursor.execute(
                'SELECT * FROM golfcourse WHERE address LIKE %s LIMIT %s',
                (f'%{zipcode}%', limit)
            )
            results = cursor.fetchall()
            
            app.logger.info(f'Zipcode search completed - Found {len(results)} courses')
            
            return jsonify({
                'success': True,
                'search_type': 'zipcode',
                'search_term': zipcode,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        # Name-based search
        elif name:
            app.logger.info(f'Performing name-based search for: {name}')
            
            cursor = db.cursor()
            cursor.execute(
                'SELECT * FROM golfcourse WHERE name ILIKE %s LIMIT %s',
                (f'%{name}%', limit)
            )
            results = cursor.fetchall()
            
            app.logger.info(f'Name search completed - Found {len(results)} courses')
            
            return jsonify({
                'success': True,
                'search_type': 'name',
                'search_term': name,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        else:
            log_security_event('MISSING_PARAMS', f'Search request missing required parameters')
            return jsonify({
                'success': False,
                'error': 'Please provide one of: lat/lng, city, zipcode, or name'
            }), 400
            
    except Exception as e:
        log_security_event('SEARCH_ERROR', f'Unexpected error: {str(e)}')
        app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route("/health")
@limiter.limit("2 per minute")
def health_check():
    """Health check endpoint for monitoring."""
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'databases': {
                'golf_courses': 'connected' if golf_courses_db_available else 'disconnected',
                'users': 'connected' if users_db_available else 'disconnected'
            },
            'security': {
                'ssl_pinning': SSL_PINNING_ENABLED,
                'rate_limiting': RATE_LIMIT_ENABLED,
                'honeypot': HONEYPOT_ENABLED
            }
        }
        
        # Test database connections
        if golf_courses_db_available:
            try:
                db = get_db()
                cursor = db.cursor()
                cursor.execute('SELECT 1')
            except Exception as e:
                health_status['databases']['golf_courses'] = 'error'
                health_status['golf_courses_error'] = str(e)
        
        if users_db_available:
            try:
                users_db = get_db()
                cursor = users_db.cursor()
                cursor.execute('SELECT 1')
            except Exception as e:
                health_status['databases']['users'] = 'error'
                health_status['users_error'] = str(e)
        
        # Determine overall status
        if not golf_courses_db_available:
            health_status['status'] = 'unhealthy'
            health_status['error'] = 'Golf courses database unavailable'
            return jsonify(health_status), 503
        
        return jsonify(health_status)
    except Exception as e:
        app.logger.error(f'Health check failed: {str(e)}')
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

def course_to_dict(row):
    """Convert database row to dictionary."""
    # pg8000 returns list of tuples with column names
    # Assuming columns are: id, name, latitude, longitude, address, website, phone, timezone, uuid
    if isinstance(row, (list, tuple)):
        return {
            'id': row[0],
            'name': row[1],
            'latitude': float(row[2]) if row[2] is not None else None,
            'longitude': float(row[3]) if row[3] is not None else None,
            'address': row[4],
            'website': row[5],
            'phone': row[6],
            'timezone': row[7],
            'uuid': row[8] if len(row) > 8 else None
        }
    else:
        # If it's a dict-like object
        return {
            'id': row[0],
            'name': row[1],
            'latitude': float(row[2]) if row[2] is not None else None,
            'longitude': float(row[3]) if row[3] is not None else None,
            'address': row[4],
            'website': row[5],
            'phone': row[6],
            'timezone': row[7],
            'uuid': row[8] if len(row) > 8 else None
        }

def user_to_dict(row):
    """Convert database row to dictionary."""
    # pg8000 returns list of tuples with column names
    # Assuming columns are: 
    if isinstance(row, (list, tuple)):
        return {
            'id': row[0],
            'uuid': row[1] if len(row) > 8 else None,
            'displayName': row[2],
            'firstConnectionDate': row[3],
            'isActive': row[4],
            'passwordResetRequired': row[5],
            'banned': row[6],
            'lastActivityDate': row[7],
            'email': row[8],
            'bannedDate': row[9],
            'bannedBy': row[10],
            'banReason': row[11],
            'role': row[12],
            'dewyPremium': row[13],
            'dewyPremiumExpiration': row[14],
            'singleGameCount': row[15]
        }
    else:
        # If it's a dict-like object
        return {
            'id': row[0],
            'uuid': row[1] if len(row) > 8 else None,
            'displayName': row[2],
            'firstConnectionDate': row[3],
            'isActive': row[4],
            'passwordResetRequired': row[5],
            'banned': row[6],
            'lastActivityDate': row[7],
            'email': row[8],
            'bannedDate': row[9],
            'bannedBy': row[10],
            'banReason': row[11],
            'role': row[12],
            'dewyPremium': row[13],
            'dewyPremiumExpiration': row[14],
            'singleGameCount': row[15]
        }
        

def get_row_value(row, index):
    """Get value from row by index - works with both SQLite Row objects and PostgreSQL tuples."""
    return row[index]

def calculate_distance(lat1, lon1, lat2, lon2):
    """Calculate the great circle distance between two points on Earth in miles."""
    R = 3959  # Earth's radius in miles
    
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    return R * c


# @app.route("/search", methods=['GET', 'POST'])
# def search_courses():
#     """
#     Search for golf courses by various criteria:
#     - lat/lng: Find nearest courses
#     - city: Search by city name
#     - zipcode: Search by zipcode
#     - name: Search by course name
#     - limit: Number of results to return (default: 10)
#     """
#     request_id = request.headers.get('X-Request-ID', 'N/A')
#     client_ip = request.remote_addr
    
#     app.logger.info(f'Search request received - Method: {request.method}, IP: {client_ip}, Request-ID: {request_id}')
    
#     try:
#         # Get parameters from query string or JSON body
#         if request.method == 'POST':
#             data = request.get_json() or {}
#             app.logger.info(f'POST request with JSON body: {data}')
#         else:
#             data = request.args.to_dict()
#             app.logger.info(f'GET request with query params: {data}')
        
#         lat = data.get('lat')
#         lng = data.get('lng')
#         city = data.get('city')
#         zipcode = data.get('zipcode')
#         name = data.get('name')
#         limit = int(data.get('limit', 10))
        
#         app.logger.info(f'Search parameters - lat: {lat}, lng: {lng}, city: {city}, zipcode: {zipcode}, name: {name}, limit: {limit}')
        
#         db = get_db()
        
#         # Search by latitude/longitude (nearest courses)
#         if lat and lng:
#             try:
#                 lat = float(lat)
#                 lng = float(lng)
                
#                 app.logger.info(f'Performing location-based search at coordinates: ({lat}, {lng})')
                
#                 # Get all courses and calculate distances
#                 app.logger.info('Querying database for all golf courses')
                
#                 courses = db.run('SELECT * FROM golfcourse')
                
#                 app.logger.info(f'Retrieved {len(courses)} courses from database')
                
#                 courses_with_distance = []
                
#                 for course in courses:
#                     course_lat = float(get_row_value(course, 2))
#                     course_lng = float(get_row_value(course, 3))
                    
#                     distance = calculate_distance(lat, lng, course_lat, course_lng)
#                     course_dict = course_to_dict(course)
#                     course_dict['distance_miles'] = round(distance, 2)
#                     courses_with_distance.append(course_dict)
                
#                 # Sort by distance and limit results
#                 courses_with_distance.sort(key=lambda x: x['distance_miles'])
#                 results = courses_with_distance[:limit]
                
#                 app.logger.info(f'Location search completed - Found {len(results)} courses within search criteria')
#                 if results:
#                     app.logger.info(f'Nearest course: {results[0]["name"]} at {results[0]["distance_miles"]} miles')
                
#                 return jsonify({
#                     'success': True,
#                     'search_type': 'location',
#                     'coordinates': {'lat': lat, 'lng': lng},
#                     'results': results,
#                     'total_found': len(results)
#                 })
                
#             except ValueError as ve:
#                 app.logger.error(f'Invalid coordinate values - lat: {lat}, lng: {lng}, error: {str(ve)}')
#                 return jsonify({
#                     'success': False,
#                     'error': 'Invalid latitude or longitude values'
#                 }), 400
        
#         # Search by city name
#         elif city:
#             app.logger.info(f'Performing city-based search for: {city}')
            
#             results = db.run(
#                 'SELECT * FROM golfcourse WHERE address ILIKE :pattern OR name ILIKE :pattern LIMIT :limit',
#                 pattern=f'%{city}%',
#                 limit=limit
#             )
            
#             app.logger.info(f'City search completed - Found {len(results)} courses matching "{city}"')
#             if results:
#                 sample_names = [get_row_value(row, 1) for row in results[:3]]
#                 app.logger.info(f'Sample results: {sample_names}')
            
#             return jsonify({
#                 'success': True,
#                 'search_type': 'city',
#                 'search_term': city,
#                 'results': [course_to_dict(row) for row in results],
#                 'total_found': len(results)
#             })
        
#         # Search by zipcode
#         elif zipcode:
#             app.logger.info(f'Performing zipcode-based search for: {zipcode}')
            
#             results = db.run(
#                 'SELECT * FROM golfcourse WHERE address ILIKE :pattern LIMIT :limit',
#                 pattern=f'%{zipcode}%',
#                 limit=limit
#             )
            
#             app.logger.info(f'Zipcode search completed - Found {len(results)} courses matching "{zipcode}"')
#             if results:
#                 sample_names = [get_row_value(row, 1) for row in results[:3]]
#                 app.logger.info(f'Sample results: {sample_names}')
            
#             return jsonify({
#                 'success': True,
#                 'search_type': 'zipcode',
#                 'search_term': zipcode,
#                 'results': [course_to_dict(row) for row in results],
#                 'total_found': len(results)
#             })
        
#         # Search by course name
#         elif name:
#             app.logger.info(f'Performing name-based search for: {name}')
            
#             results = db.run(
#                 'SELECT * FROM golfcourse WHERE name ILIKE :pattern LIMIT :limit',
#                 pattern=f'%{name}%',
#                 limit=limit
#             )
            
#             app.logger.info(f'Name search completed - Found {len(results)} courses matching "{name}"')
#             if results:
#                 sample_names = [get_row_value(row, 1) for row in results[:3]]
#                 app.logger.info(f'Sample results: {sample_names}')
            
#             return jsonify({
#                 'success': True,
#                 'search_type': 'name',
#                 'search_term': name,
#                 'results': [course_to_dict(row) for row in results],
#                 'total_found': len(results)
#             })
        
#         else:
#             app.logger.warning(f'Search request missing required parameters - Provided data: {data}')
#             return jsonify({
#                 'success': False,
#                 'error': 'Please provide one of: lat/lng, city, zipcode, or name'
#             }), 400
            
#     except Exception as e:
#         app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500

# @app.route("/authenticate", methods=['GET', 'POST'])
# def authenticate():
#     """
#     Recieve user information or create a new user
#     """
#     request_id = request.headers.get('X-Request-ID', 'N/A')
#     client_ip = request.remote_addr
    
#     app.logger.info(f'Authenticate request received - Method: {request.method}, IP: {client_ip}, Request-ID: {request_id}')
    
#     try:
#         # Get parameters from query string or JSON body
#         if request.method == 'POST':
#             data = request.get_json() or {}
#             app.logger.info(f'POST request with JSON body: {data}')
#         else:
#             data = request.args.to_dict()
#             app.logger.info(f'GET request with query params: {data}')

#         apiKey = data.get('apiKey')
#         limit = int(data.get('limit', 1))
        
#         app.logger.info(f'apiKey parameters - apiKey {apiKey}')
        
#         db = get_db()

#         if apiKey:
#             app.logger.info(f'Performing apiKey search for: {apiKey}')
            
#             results = db.run(
#                 'SELECT * FROM users WHERE uuid ILIKE :pattern LIMIT :limit',
#                 pattern=f'%{apiKey}%',
#                 limit=limit
#             )
            
#             app.logger.info(f'apiKey search completed - Found {len(results)} users matching "{apiKey}"')
#             if results:
#                 sample_names = [get_row_value(row, 1) for row in results[:3]]
#                 app.logger.info(f'Sample results: {sample_names}')
            
#             return jsonify({
#                 'success': True,
#                 'search_type': 'apiKey',
#                 'search_term': apiKey,
#                 'results': [user_to_dict(row) for row in results],
#                 'total_found': len(results)
#             })
        
#         else:
#             app.logger.warning(f'Authenticate request missing required parameters - Provided data: {data}')
#             return jsonify({
#                 'success': False,
#                 'error': 'Please provide an apiKey'
#             }), 400
            
#     except Exception as e:
#         app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
#         return jsonify({
#             'success': False,
#             'error': str(e)
#         }), 500




# ============================================================================
# DB CONNECTIONS
# ============================================================================
def init_db():
    """Initialize the database with required tables."""
    try:
        import pg8000.native
            
        parsed = urlparse(DATABASE)
        username = parsed.username
        password = parsed.password
        host = parsed.hostname
        port = parsed.port or 5432
        database = parsed.path.lstrip('/')
        query_params = parse_qs(parsed.query)
        ssl_mode = query_params.get('sslmode', ['prefer'])[0]
        
        app.logger.info('Initializing PostgreSQL database tables')
        
        if ssl_mode == 'require':
            conn = pg8000.native.Connection(
                user=username,
                password=password,
                host=host,
                port=port,
                database=database,
                ssl_context=True
            )
        else:
            conn = pg8000.native.Connection(
                user=username,
                password=password,
                host=host,
                port=port,
                database=database
            )
        
        conn.run('''
            CREATE TABLE IF NOT EXISTS golfcourse (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                address TEXT,
                website TEXT,
                phone TEXT,
                timezone TEXT,
                uuid TEXT DEFAULT 'constant'
            )
        ''')

        conn.run('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                uuid TEXT NOT NULL DEFAULT '',
                "displayName" TEXT NOT NULL DEFAULT '',
                "firstConnectionDate" TEXT NOT NULL DEFAULT '',
                "isActive" BOOLEAN NOT NULL DEFAULT true,
                "passwordResetRequired" BOOLEAN NOT NULL DEFAULT false,
                banned BOOLEAN NOT NULL DEFAULT false,
                "lastActivityDate" TEXT,
                email TEXT,
                "bannedDate" TEXT,
                "bannedBy" TEXT,
                "banReason" TEXT,
                role TEXT,
                "dewyPremium" BOOLEAN NOT NULL DEFAULT false,
                "dewyPremiumExpiration" TEXT,
                "singleGameCount" INTEGER
            )
        ''')
        
        conn.close()
        app.logger.info('PostgreSQL database tables created successfully')

        return True
    except Exception as e:
        app.logger.error(f'Failed to initialize database: {str(e)}', exc_info=True)
        return False

def get_db():
    """Get database connection for the current request."""
    db = getattr(g, '_database', None)
    if db is None:
        try:
            import pg8000.native
            
            # Parse the PostgreSQL URL
            parsed = urlparse(DATABASE)
            
            # Extract connection parameters
            username = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or 5432
            database = parsed.path.lstrip('/')
            
            # Parse query parameters for SSL settings
            query_params = parse_qs(parsed.query)
            ssl_mode = query_params.get('sslmode', ['prefer'])[0]
            
            app.logger.info(f'Connecting to PostgreSQL: host={host}, port={port}, database={database}, user={username}, sslmode={ssl_mode}')
            
            # Create connection with SSL if required
            if ssl_mode == 'require':
                db = g._database = pg8000.native.Connection(
                    user=username,
                    password=password,
                    host=host,
                    port=port,
                    database=database,
                    ssl_context=True
                )
            else:
                db = g._database = pg8000.native.Connection(
                    user=username,
                    password=password,
                    host=host,
                    port=port,
                    database=database
                )
            
            app.logger.info('PostgreSQL connection established successfully')
            
        except ImportError:
            app.logger.error('pg8000 not installed. Install with: pip install pg8000')
            raise
        except Exception as e:
            app.logger.error(f'Failed to connect to PostgreSQL: {str(e)}', exc_info=True)
            raise
    return db

@app.teardown_appcontext
def close_db(error):
    """Close database connections."""
    db = g.pop('db', None)
    if db is not None:
        db.close()
    
    users_db = g.pop('users_db', None)
    if users_db is not None:
        users_db.close()

def test_golf_courses_db_connection():
    """Test connection to golf courses database."""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT 1')
        app.logger.info(f'Golf courses database connection successful')
        return True
    except Exception as e:
        app.logger.error(f'Golf courses database connection failed: {str(e)}')
        return False

def test_users_db_connection():
    """Test connection to users database."""
    try:
        users_db = get_db()
        cursor = users_db.cursor()
        cursor.execute('SELECT 1')
        app.logger.info(f'Users database connection successful')
        return True
    except Exception as e:
        app.logger.error(f'Users database connection failed: {str(e)}')
        return False


# ============================================================================
# INITIALIZATION
# ============================================================================

# Test database connections on startup
golf_courses_db_available = False
users_db_available = False

# Test golf courses database connection
if test_golf_courses_db_connection():
    golf_courses_db_available = True
    try:
        db = database
        cursor = db.cursor()
        cursor.execute('SELECT COUNT(*) FROM golfcourse')
        result = cursor.fetchone()
        course_count = result[0] if result else 0
        app.logger.info(f'Golf courses database ready - Total courses: {course_count}')
    except Exception as e:
        app.logger.warning(f'Golf courses database connected but table may not exist: {str(e)}')
else:
    app.logger.error('Golf courses database connection failed - API will not function properly')

# Test users database connection
if test_users_db_connection():
    users_db_available = True
    try:
        users_db = database()
        cursor = users_db.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        result = cursor.fetchone()
        user_count = result[0] if result else 0
        app.logger.info(f'Users database ready - Total users: {user_count}')
    except Exception as e:
        app.logger.warning(f'Users database connected but table may not exist: {str(e)}')
else:
    app.logger.error('Users database connection failed - User features will not be available')

# Log overall status
if golf_courses_db_available and users_db_available:
    app.logger.info('All database connections successful - API fully operational')
elif golf_courses_db_available:
    app.logger.warning('Only golf courses database available - User features disabled')
else:
    app.logger.error('Critical: No database connections available - API will not function')

app.logger.info('Security features enabled:')
app.logger.info(f'- SSL Pinning: {SSL_PINNING_ENABLED}')
app.logger.info(f'- Rate Limiting: {RATE_LIMIT_ENABLED}')
app.logger.info(f'- Honeypot: {HONEYPOT_ENABLED}')
app.logger.info(f'- Max Requests per API Key: {MAX_REQUESTS_PER_API_KEY}/24h')

if __name__ == '__main__':
    app.logger.info('Starting Flask server')
    app.run(debug=True)
    init_db()