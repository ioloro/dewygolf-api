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

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['API_KEYS'] = os.environ.get('API_KEYS', '').split(',') if os.environ.get('API_KEYS') else []
app.config['RATE_LIMIT_ENABLED'] = os.environ.get('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
app.config['CORS_ORIGINS'] = os.environ.get('CORS_ORIGINS', '').split(',') if os.environ.get('CORS_ORIGINS') else ['*']

# Initialize Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"] if app.config['RATE_LIMIT_ENABLED'] else []
)

# Initialize CORS
cors = CORS(app, origins=app.config['CORS_ORIGINS'])

# Security Headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# API Key Authentication
def require_api_key(f):
    """Decorator to require API key authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            app.logger.warning(f'API request without key from {request.remote_addr}')
            return jsonify({'error': 'API key required'}), 401
        
        if api_key not in app.config['API_KEYS']:
            app.logger.warning(f'Invalid API key attempt from {request.remote_addr}')
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Input Validation
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
    text = re.sub(r'[<>"\'&]', '', text)
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

# Enhanced Logging
def log_security_event(event_type, details):
    """Log security-related events."""
    app.logger.warning(f'SECURITY_EVENT: {event_type} - {details} - IP: {request.remote_addr} - User-Agent: {request.headers.get("User-Agent", "Unknown")}')

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
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(logging.INFO)
    
    # Configure app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info('Golf Course API startup')

setup_logging()

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///golfcourses.db')
app.logger.info(f'DATABASE_URL: {DATABASE_URL}')

# Parse DATABASE_URL to determine database type
if DATABASE_URL.startswith('postgresql://') or DATABASE_URL.startswith('postgres://'):
    DB_TYPE = 'postgresql'
    DATABASE = DATABASE_URL
    app.logger.info('Using PostgreSQL database with pg8000')
elif DATABASE_URL.startswith('sqlite:///'):
    DB_TYPE = 'sqlite'
    DATABASE = DATABASE_URL.replace('sqlite:///', '')
    app.logger.info(f'Using SQLite database: {DATABASE}')
elif DATABASE_URL.startswith('sqlite://'):
    DB_TYPE = 'sqlite'
    DATABASE = DATABASE_URL.replace('sqlite://', '')
    app.logger.info(f'Using SQLite database: {DATABASE}')
else:
    # Default to SQLite
    DB_TYPE = 'sqlite'
    DATABASE = DATABASE_URL
    app.logger.info(f'Using SQLite database (default): {DATABASE}')

def get_db():
    """Get database connection for the current request."""
    db = getattr(g, '_database', None)
    if db is None:
        if DB_TYPE == 'postgresql':
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
        else:
            db = g._database = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row
            app.logger.debug('SQLite connection established')
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        app.logger.debug('Database connection closed')

def init_db():
    """Initialize the database with required tables."""
    try:
        if DB_TYPE == 'postgresql':
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
            
            conn.close()
            app.logger.info('PostgreSQL database tables created successfully')
        else:
            app.logger.info('Initializing SQLite database tables')
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS golfcourse (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            
            conn.commit()
            conn.close()
            app.logger.info('SQLite database tables created successfully')
        return True
    except Exception as e:
        app.logger.error(f'Failed to initialize database: {str(e)}', exc_info=True)
        return False

def course_to_dict(row):
    """Convert database row to dictionary."""
    if DB_TYPE == 'postgresql':
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
    else:
        # SQLite with row_factory
        return {
            'id': row['id'],
            'name': row['name'],
            'latitude': float(row['latitude']),
            'longitude': float(row['longitude']),
            'address': row['address'],
            'website': row['website'],
            'phone': row['phone'],
            'timezone': row['timezone'],
            'uuid': row['uuid']
        }

def get_row_value(row, index):
    """Get value from row by index - works with both SQLite Row objects and PostgreSQL tuples."""
    if DB_TYPE == 'postgresql':
        return row[index]
    else:
        # For SQLite, we can still use index
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

@app.route("/")
@limiter.limit("10 per minute")
def root_route():
    """Root route with rate limiting."""
    return redirect("https://www.dewygolf.com", code=302)

@app.route("/search", methods=['GET', 'POST'])
@limiter.limit("60 per minute")
@require_api_key
def search_courses():
    """
    Search for golf courses by various criteria:
    - lat/lng: Find nearest courses
    - city: Search by city name
    - zipcode: Search by zipcode
    - name: Search by course name
    - limit: Number of results to return (default: 10)
    
    Requires API key authentication.
    """
    request_id = request.headers.get('X-Request-ID', 'N/A')
    client_ip = request.remote_addr
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    
    app.logger.info(f'Search request received - Method: {request.method}, IP: {client_ip}, Request-ID: {request_id}, API-Key: {api_key[:8]}...')
    
    try:
        # Get parameters from query string or JSON body
        if request.method == 'POST':
            data = request.get_json() or {}
            app.logger.info(f'POST request with JSON body: {data}')
        else:
            data = request.args.to_dict()
            app.logger.info(f'GET request with query params: {data}')
        
        # Validate and sanitize input parameters
        try:
            validated_data = validate_search_params(data)
        except ValueError as e:
            log_security_event('INVALID_INPUT', f'Validation failed: {str(e)}')
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        lat = validated_data.get('lat')
        lng = validated_data.get('lng')
        city = validated_data.get('city')
        zipcode = validated_data.get('zipcode')
        name = validated_data.get('name')
        limit = validated_data.get('limit')
        
        app.logger.info(f'Search parameters - lat: {lat}, lng: {lng}, city: {city}, zipcode: {zipcode}, name: {name}, limit: {limit}')
        
        db = get_db()
        
        # Search by latitude/longitude (nearest courses)
        if lat and lng:
            try:
                app.logger.info(f'Performing location-based search at coordinates: ({lat}, {lng})')
                
                # Get all courses and calculate distances
                app.logger.info('Querying database for all golf courses')
                
                if DB_TYPE == 'postgresql':
                    courses = db.run('SELECT * FROM golfcourse')
                else:
                    cursor = db.cursor()
                    cursor.execute('SELECT * FROM golfcourse')
                    courses = cursor.fetchall()
                
                app.logger.info(f'Retrieved {len(courses)} courses from database')
                
                courses_with_distance = []
                
                for course in courses:
                    course_lat = float(get_row_value(course, 2))
                    course_lng = float(get_row_value(course, 3))
                    
                    distance = calculate_distance(lat, lng, course_lat, course_lng)
                    course_dict = course_to_dict(course)
                    course_dict['distance_miles'] = round(distance, 2)
                    courses_with_distance.append(course_dict)
                
                # Sort by distance and limit results
                courses_with_distance.sort(key=lambda x: x['distance_miles'])
                results = courses_with_distance[:limit]
                
                app.logger.info(f'Location search completed - Found {len(results)} courses within search criteria')
                if results:
                    app.logger.info(f'Nearest course: {results[0]["name"]} at {results[0]["distance_miles"]} miles')
                
                return jsonify({
                    'success': True,
                    'search_type': 'location',
                    'coordinates': {'lat': lat, 'lng': lng},
                    'results': results,
                    'total_found': len(results)
                })
                
            except Exception as e:
                log_security_event('COORDINATE_ERROR', f'Error processing coordinates: {str(e)}')
                app.logger.error(f'Error in location search: {str(e)}')
                return jsonify({
                    'success': False,
                    'error': 'Error processing location search'
                }), 400
        
        # Search by city name
        elif city:
            app.logger.info(f'Performing city-based search for: {city}')
            
            if DB_TYPE == 'postgresql':
                results = db.run(
                    'SELECT * FROM golfcourse WHERE address ILIKE :pattern OR name ILIKE :pattern LIMIT :limit',
                    pattern=f'%{city}%',
                    limit=limit
                )
            else:
                cursor = db.cursor()
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address LIKE ? OR name LIKE ?
                    LIMIT ?
                ''', (f'%{city}%', f'%{city}%', limit))
                results = cursor.fetchall()
            
            app.logger.info(f'City search completed - Found {len(results)} courses matching "{city}"')
            if results:
                sample_names = [get_row_value(row, 1) for row in results[:3]]
                app.logger.info(f'Sample results: {sample_names}')
            
            return jsonify({
                'success': True,
                'search_type': 'city',
                'search_term': city,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        # Search by zipcode
        elif zipcode:
            app.logger.info(f'Performing zipcode-based search for: {zipcode}')
            
            if DB_TYPE == 'postgresql':
                results = db.run(
                    'SELECT * FROM golfcourse WHERE address ILIKE :pattern LIMIT :limit',
                    pattern=f'%{zipcode}%',
                    limit=limit
                )
            else:
                cursor = db.cursor()
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address LIKE ?
                    LIMIT ?
                ''', (f'%{zipcode}%', limit))
                results = cursor.fetchall()
            
            app.logger.info(f'Zipcode search completed - Found {len(results)} courses matching "{zipcode}"')
            if results:
                sample_names = [get_row_value(row, 1) for row in results[:3]]
                app.logger.info(f'Sample results: {sample_names}')
            
            return jsonify({
                'success': True,
                'search_type': 'zipcode',
                'search_term': zipcode,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        # Search by course name
        elif name:
            app.logger.info(f'Performing name-based search for: {name}')
            
            if DB_TYPE == 'postgresql':
                results = db.run(
                    'SELECT * FROM golfcourse WHERE name ILIKE :pattern LIMIT :limit',
                    pattern=f'%{name}%',
                    limit=limit
                )
            else:
                cursor = db.cursor()
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE name LIKE ?
                    LIMIT ?
                ''', (f'%{name}%', limit))
                results = cursor.fetchall()
            
            app.logger.info(f'Name search completed - Found {len(results)} courses matching "{name}"')
            if results:
                sample_names = [get_row_value(row, 1) for row in results[:3]]
                app.logger.info(f'Sample results: {sample_names}')
            
            return jsonify({
                'success': True,
                'search_type': 'name',
                'search_term': name,
                'results': [course_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        else:
            log_security_event('MISSING_PARAMS', f'Search request missing required parameters - Provided data: {data}')
            app.logger.warning(f'Search request missing required parameters - Provided data: {data}')
            return jsonify({
                'success': False,
                'error': 'Please provide one of: lat/lng, city, zipcode, or name'
            }), 400
            
    except Exception as e:
        log_security_event('SEARCH_ERROR', f'Unexpected error in search endpoint: {str(e)}')
        app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

@app.route("/health")
@limiter.limit("30 per minute")
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Test database connection
        db = get_db()
        if DB_TYPE == 'postgresql':
            result = db.run('SELECT 1')
        else:
            cursor = db.cursor()
            cursor.execute('SELECT 1')
            result = cursor.fetchone()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected'
        })
    except Exception as e:
        app.logger.error(f'Health check failed: {str(e)}')
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@app.route("/api-info")
@limiter.limit("10 per minute")
def api_info():
    """API information endpoint."""
    return jsonify({
        'name': 'Dewy Golf Course API',
        'version': '1.0.0',
        'description': 'Golf course search API with location-based and text search capabilities',
        'authentication': 'API key required',
        'rate_limits': {
            'search': '60 requests per minute',
            'health': '30 requests per minute',
            'root': '10 requests per minute'
        },
        'endpoints': {
            'search': '/search - Search golf courses',
            'health': '/health - Health check',
            'api_info': '/api-info - This information'
        }
    })

# Initialize database on startup
if init_db():
    try:
        if DB_TYPE == 'postgresql':
            import pg8000.native
            
            parsed = urlparse(DATABASE)
            username = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or 5432
            database = parsed.path.lstrip('/')
            query_params = parse_qs(parsed.query)
            ssl_mode = query_params.get('sslmode', ['prefer'])[0]
            
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
            
            result = conn.run('SELECT COUNT(*) FROM golfcourse')
            course_count = result[0][0]
            conn.close()
            app.logger.info(f'PostgreSQL connection successful - Total courses in database: {course_count}')
        else:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM golfcourse')
            course_count = cursor.fetchone()[0]
            conn.close()
            app.logger.info(f'SQLite connection successful - Total courses in database: {course_count}')
    except Exception as e:
        app.logger.error(f'Database connection test failed: {str(e)}', exc_info=True)

if __name__ == '__main__':
    app.logger.info('Starting Flask development server')
    app.run(debug=True)
