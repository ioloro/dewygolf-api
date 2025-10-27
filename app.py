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
        app.logger.debug(f'require_api_key decorator called for endpoint: {request.endpoint}')
        app.logger.debug(f'Request method: {request.method}, Path: {request.path}')
        app.logger.debug(f'Request from: {request.remote_addr}, User-Agent: {request.headers.get("User-Agent", "N/A")}')
        
        # Extract API key from headers or query params
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        app.logger.debug(f'API key source: {"header" if request.headers.get("X-API-Key") else "query_param" if request.args.get("api_key") else "none"}')
        
        if not api_key:
            app.logger.warning(f'API request without key from {request.remote_addr} to {request.endpoint}')
            log_security_event('API_KEY_MISSING', f'No API key provided from {request.remote_addr}')
            return jsonify({'error': 'API key required'}), 401
        
        # Mask API key for logging (show first 8 chars only)
        masked_key = f'{api_key[:8]}...' if len(api_key) > 8 else '***'
        app.logger.debug(f'API key received: {masked_key}')
        
        # Check if users database is available
        app.logger.debug(f'Checking users database availability: {users_db_available}')
        if not users_db_available:
            app.logger.warning(f'Users database unavailable - falling back to config check for key {masked_key}')
            app.logger.debug(f'Number of API keys in config: {len(app.config.get("API_KEYS", []))}')
            
            if api_key not in app.config.get('API_KEYS', []):
                app.logger.warning(f'Invalid API key attempt from {request.remote_addr} (key: {masked_key})')
                log_security_event('INVALID_API_KEY_CONFIG', f'Invalid key {masked_key} from {request.remote_addr}')
                return jsonify({'error': 'Invalid API key'}), 401
            
            app.logger.info(f'Valid API key from config for {request.remote_addr} (key: {masked_key})')
            return f(*args, **kwargs)
        
        try:
            app.logger.debug('Attempting to get users database connection')
            users_db = get_users_db()
            app.logger.debug(f'Users database connection obtained: {type(users_db)}')
            
            # Check if API key exists in database
            app.logger.debug(f'Querying database for API key {masked_key} (DB type: {USERS_DB_TYPE})')
            
            if USERS_DB_TYPE == 'postgresql':
                app.logger.debug('Executing PostgreSQL query for API key lookup')
                try:
                    result = users_db.run(
                        'SELECT api_key, is_banned FROM users WHERE api_key = :api_key',
                        api_key=api_key
                    )
                    user = result[0] if result else None
                    app.logger.debug(f'PostgreSQL query result: {"user found" if user else "no user found"}')
                except Exception as pg_err:
                    app.logger.error(f'PostgreSQL query error: {str(pg_err)}', exc_info=True)
                    raise
            else:
                app.logger.debug('Executing SQLite query for API key lookup')
                try:
                    cursor = users_db.cursor()
                    cursor.execute(
                        'SELECT api_key, is_banned FROM users WHERE api_key = ?',
                        (api_key,)
                    )
                    user = cursor.fetchone()
                    app.logger.debug(f'SQLite query result: {"user found" if user else "no user found"}')
                except Exception as sqlite_err:
                    app.logger.error(f'SQLite query error: {str(sqlite_err)}', exc_info=True)
                    raise
            
            if user:
                app.logger.debug(f'User record found for key {masked_key}')
                
                # Check if user is banned
                is_banned = user[1] if isinstance(user, (tuple, list)) else user['is_banned']
                app.logger.debug(f'User banned status: {is_banned}')
                
                if is_banned:
                    app.logger.warning(f'Banned API key attempt from {request.remote_addr} (key: {masked_key})')
                    log_security_event('BANNED_API_KEY_ATTEMPT', f'Banned key {masked_key} used from {request.remote_addr}')
                    return jsonify({'error': 'API key has been banned'}), 403
                
                # Valid API key, not banned - allow access
                app.logger.info(f'Valid API key access from {request.remote_addr} to {request.endpoint} (key: {masked_key})')
                log_security_event('API_KEY_SUCCESS', f'Valid key {masked_key} from {request.remote_addr}')
                return f(*args, **kwargs)
            else:
                # API key doesn't exist - add it to the database
                app.logger.info(f'New API key detected from {request.remote_addr} (key: {masked_key}), adding to database')
                
                try:
                    current_time = datetime.utcnow()
                    app.logger.debug(f'Current UTC time for new user: {current_time.isoformat()}')
                    
                    if USERS_DB_TYPE == 'postgresql':
                        app.logger.debug('Inserting new user into PostgreSQL')
                        users_db.run(
                            '''INSERT INTO users (api_key, is_banned, created_at, last_used_at) 
                               VALUES (:api_key, :is_banned, :created_at, :last_used_at)''',
                            api_key=api_key,
                            is_banned=False,
                            created_at=current_time,
                            last_used_at=current_time
                        )
                        app.logger.debug('PostgreSQL insert completed')
                    else:
                        app.logger.debug('Inserting new user into SQLite')
                        cursor = users_db.cursor()
                        cursor.execute(
                            '''INSERT INTO users (api_key, is_banned, created_at, last_used_at) 
                               VALUES (?, ?, ?, ?)''',
                            (api_key, False, current_time.isoformat(), current_time.isoformat())
                        )
                        users_db.commit()
                        app.logger.debug(f'SQLite insert completed, rows affected: {cursor.rowcount}')
                    
                    app.logger.info(f'Successfully added new API key to database (key: {masked_key})')
                    log_security_event('NEW_API_KEY_ADDED', f'New key {masked_key} added from {request.remote_addr}')
                    return f(*args, **kwargs)
                    
                except Exception as insert_err:
                    app.logger.error(f'Error inserting new API key into database: {str(insert_err)}', exc_info=True)
                    app.logger.error(f'Insert error type: {type(insert_err).__name__}')
                    log_security_event('API_KEY_INSERT_ERROR', f'Failed to add key {masked_key}: {str(insert_err)}')
                    return jsonify({'error': 'Failed to register API key'}), 500
                
        except Exception as e:
            app.logger.error(f'Error checking API key in database: {str(e)}', exc_info=True)
            app.logger.error(f'Exception type: {type(e).__name__}')
            app.logger.error(f'Endpoint: {request.endpoint}, Remote addr: {request.remote_addr}')
            log_security_event('API_KEY_CHECK_ERROR', f'Database error for {masked_key}: {str(e)}')
            return jsonify({'error': 'Internal server error during authentication'}), 500
    
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
USERS_DATABASE_URL = os.environ.get('USERS_DATABASE_URL', 'sqlite:///users.db')

app.logger.info(f'DATABASE_URL: {DATABASE_URL}')
app.logger.info(f'USERS_DATABASE_URL: {USERS_DATABASE_URL}')

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

# Parse USERS_DATABASE_URL
if USERS_DATABASE_URL.startswith('postgresql://') or USERS_DATABASE_URL.startswith('postgres://'):
    USERS_DB_TYPE = 'postgresql'
    USERS_DATABASE = USERS_DATABASE_URL
    app.logger.info('Using PostgreSQL for users database with pg8000')
elif USERS_DATABASE_URL.startswith('sqlite:///'):
    USERS_DB_TYPE = 'sqlite'
    USERS_DATABASE = USERS_DATABASE_URL.replace('sqlite:///', '')
    app.logger.info(f'Using SQLite for users database: {USERS_DATABASE}')
elif USERS_DATABASE_URL.startswith('sqlite://'):
    USERS_DB_TYPE = 'sqlite'
    USERS_DATABASE = USERS_DATABASE_URL.replace('sqlite://', '')
    app.logger.info(f'Using SQLite for users database: {USERS_DATABASE}')
else:
    # Default to SQLite
    USERS_DB_TYPE = 'sqlite'
    USERS_DATABASE = USERS_DATABASE_URL
    app.logger.info(f'Using SQLite for users database (default): {USERS_DATABASE}')

def get_db():
    """Get golf courses database connection for the current request."""
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

def get_users_db():
    """Get users database connection for the current request."""
    app.logger.debug('get_users_db() called - checking for existing connection')
    
    users_db = getattr(g, '_users_database', None)
    
    if users_db is None:
        app.logger.info('No existing users database connection found in request context - creating new connection')
        app.logger.debug(f'Database type configured: {USERS_DB_TYPE}')
        
        if USERS_DB_TYPE == 'postgresql':
            app.logger.info('Initiating PostgreSQL connection for users database')
            
            try:
                app.logger.debug('Attempting to import pg8000.native')
                import pg8000.native
                app.logger.debug('pg8000.native imported successfully')
                
                # Parse the PostgreSQL URL
                app.logger.debug(f'Parsing PostgreSQL URL: {USERS_DATABASE[:20]}...[REDACTED]')
                parsed = urlparse(USERS_DATABASE)
                
                # Extract connection parameters
                username = parsed.username
                password = parsed.password
                host = parsed.hostname
                port = parsed.port or 5432
                database = parsed.path.lstrip('/')
                
                app.logger.debug(f'Extracted connection parameters: username={username}, host={host}, port={port}, database={database}')
                
                # Parse query parameters for SSL settings
                query_params = parse_qs(parsed.query)
                ssl_mode = query_params.get('sslmode', ['prefer'])[0]
                
                app.logger.debug(f'Parsed query parameters: {list(query_params.keys())}')
                app.logger.info(f'Connecting to PostgreSQL database "{database}": host={host}, port={port}, user={username}, sslmode={ssl_mode}')
                
                # Create connection with SSL if required
                if ssl_mode == 'require':
                    app.logger.debug('SSL mode is "require" - creating connection with SSL context')
                    try:
                        users_db = g._users_database = pg8000.native.Connection(
                            user=username,
                            password=password,
                            host=host,
                            port=port,
                            database=database,
                            ssl_context=True
                        )
                        app.logger.debug('PostgreSQL connection object created with SSL')
                    except Exception as ssl_error:
                        app.logger.error(f'Failed to create SSL connection: {str(ssl_error)}', exc_info=True)
                        raise
                else:
                    app.logger.debug(f'SSL mode is "{ssl_mode}" - creating connection without explicit SSL context')
                    try:
                        users_db = g._users_database = pg8000.native.Connection(
                            user=username,
                            password=password,
                            host=host,
                            port=port,
                            database=database
                        )
                        app.logger.debug('PostgreSQL connection object created without SSL')
                    except Exception as conn_error:
                        app.logger.error(f'Failed to create connection: {str(conn_error)}', exc_info=True)
                        raise
                
                app.logger.info(f'PostgreSQL connection to database "{database}" established successfully')
                app.logger.debug(f'Connection stored in g._users_database: {type(users_db)}')
                
                # Verify required tables exist - THIS IS CRITICAL
                app.logger.debug(f'Verifying required tables exist in database "{database}"')
                try:
                    # Get all tables in the database
                    all_tables_result = users_db.run(
                        """SELECT table_name 
                           FROM information_schema.tables 
                           WHERE table_schema = 'public' 
                           ORDER BY table_name"""
                    )
                    table_names = [row[0] for row in all_tables_result] if all_tables_result else []
                    app.logger.info(f'Tables found in database "{database}": {table_names}')
                    app.logger.debug(f'Total tables found: {len(table_names)}')
                    
                    # Check for required tables
                    required_tables = ['users', 'golfCourses']
                    missing_tables = [table for table in required_tables if table not in table_names]
                    
                    if missing_tables:
                        app.logger.error(f'CRITICAL ERROR: Required tables missing from database "{database}": {missing_tables}')
                        app.logger.error(f'Expected tables: {required_tables}')
                        app.logger.error(f'Found tables: {table_names}')
                        
                        if not table_names:
                            app.logger.error('Database is completely empty - no tables found!')
                        
                        # FAIL HARD - raise exception
                        raise RuntimeError(
                            f'Required tables missing from database "{database}": {missing_tables}. '
                            f'Expected: {required_tables}, Found: {table_names}. '
                            f'Please run database migrations or create the missing tables.'
                        )
                    
                    app.logger.info(f'All required tables verified in database "{database}": {required_tables}')
                    
                except RuntimeError:
                    # Re-raise our custom error
                    raise
                except Exception as table_check_err:
                    app.logger.error(f'Error checking for required tables: {str(table_check_err)}', exc_info=True)
                    raise RuntimeError(f'Failed to verify required tables: {str(table_check_err)}')
                
            except ImportError as import_err:
                app.logger.error(f'pg8000 import failed: {str(import_err)}')
                app.logger.error('pg8000 not installed. Install with: pip install pg8000')
                app.logger.debug('Import error details:', exc_info=True)
                raise
            except Exception as e:
                app.logger.error(f'Failed to connect to PostgreSQL: {str(e)}', exc_info=True)
                app.logger.error(f'Exception type: {type(e).__name__}')
                if 'host' in locals():
                    app.logger.debug(f'Connection parameters that failed: host={host}, port={port}, database={database}, user={username}')
                raise
        else:
            app.logger.info(f'Using SQLite database: {USERS_DATABASE}')
            app.logger.debug('Attempting to connect to SQLite database')
            
            try:
                users_db = g._users_database = sqlite3.connect(USERS_DATABASE)
                app.logger.debug(f'SQLite connection created: {type(users_db)}')
                
                users_db.row_factory = sqlite3.Row
                app.logger.debug('SQLite row_factory set to sqlite3.Row')
                
                app.logger.info('SQLite connection established')
                app.logger.debug(f'SQLite database file: {USERS_DATABASE}')
                
                # Verify required tables exist - THIS IS CRITICAL
                app.logger.debug('Verifying required tables exist in SQLite database')
                try:
                    cursor = users_db.cursor()
                    
                    # Get all tables in the database
                    cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                    all_tables = cursor.fetchall()
                    table_names = [row[0] for row in all_tables] if all_tables else []
                    app.logger.info(f'Tables found in database: {table_names}')
                    app.logger.debug(f'Total tables found: {len(table_names)}')
                    
                    # Check for required tables
                    required_tables = ['users', 'golfCourses']
                    missing_tables = [table for table in required_tables if table not in table_names]
                    
                    if missing_tables:
                        app.logger.error(f'CRITICAL ERROR: Required tables missing from database: {missing_tables}')
                        app.logger.error(f'Expected tables: {required_tables}')
                        app.logger.error(f'Found tables: {table_names}')
                        
                        if not table_names:
                            app.logger.error('Database is completely empty - no tables found!')
                        
                        # FAIL HARD - raise exception
                        raise RuntimeError(
                            f'Required tables missing from database: {missing_tables}. '
                            f'Expected: {required_tables}, Found: {table_names}. '
                            f'Please run database migrations or create the missing tables.'
                        )
                    
                    app.logger.info(f'All required tables verified in database: {required_tables}')
                    
                except RuntimeError:
                    # Re-raise our custom error
                    raise
                except Exception as table_check_err:
                    app.logger.error(f'Error checking for required tables: {str(table_check_err)}', exc_info=True)
                    raise RuntimeError(f'Failed to verify required tables: {str(table_check_err)}')
                
            except sqlite3.Error as sqlite_err:
                app.logger.error(f'SQLite connection error: {str(sqlite_err)}', exc_info=True)
                app.logger.error(f'Database path: {USERS_DATABASE}')
                raise
            except Exception as e:
                app.logger.error(f'Unexpected error connecting to SQLite: {str(e)}', exc_info=True)
                raise
    else:
        app.logger.debug('Reusing existing database connection from request context')
        app.logger.debug(f'Connection type: {type(users_db)}')
    
    app.logger.debug('get_users_db() returning connection')
    return users_db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connections at the end of request."""
    # Close golf courses database
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        app.logger.debug('Golf courses database connection closed')
    
    # Close users database
    users_db = getattr(g, '_users_database', None)
    if users_db is not None:
        users_db.close()
        app.logger.debug('Users database connection closed')

def test_golf_courses_db_connection():
    """Test connection to golf courses database."""
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
            
            app.logger.info('Testing PostgreSQL golf courses database connection')
            
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
            
            # Test connection with a simple query
            result = conn.run('SELECT 1')
            conn.close()
            app.logger.info('PostgreSQL golf courses database connection successful')
            return True
        else:
            app.logger.info('Testing SQLite golf courses database connection')
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            app.logger.info('SQLite golf courses database connection successful')
            return True
    except Exception as e:
        app.logger.error(f'Failed to connect to golf courses database: {str(e)}', exc_info=True)
        return False

def test_users_db_connection():
    """Test connection to users database."""
    try:
        if USERS_DB_TYPE == 'postgresql':
            import pg8000.native
            
            parsed = urlparse(USERS_DATABASE)
            username = parsed.username
            password = parsed.password
            host = parsed.hostname
            port = parsed.port or 5432
            database = parsed.path.lstrip('/')
            query_params = parse_qs(parsed.query)
            ssl_mode = query_params.get('sslmode', ['prefer'])[0]
            
            app.logger.info('Testing PostgreSQL users database connection')
            
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
            
            # Test connection with a simple query
            result = conn.run('SELECT 1')
            conn.close()
            app.logger.info('PostgreSQL users database connection successful')
            return True
        else:
            app.logger.info('Testing SQLite users database connection')
            conn = sqlite3.connect(USERS_DATABASE)
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            app.logger.info('SQLite users database connection successful')
            return True
    except Exception as e:
        app.logger.error(f'Failed to connect to users database: {str(e)}', exc_info=True)
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

def user_to_dict(row):
    """Convert users database row to dictionary."""
    if USERS_DB_TYPE == 'postgresql':
        # pg8000 returns list of tuples with column names
        # Assuming columns are: id, uuid, displayName, firstConnectionDate, lastActivityDate, isActive, email, passwordResetRequired, banned, bannedDate, bannedBy, banReason, role
        if isinstance(row, (list, tuple)):
            return {
                'id': row[0],
                'uuid': row[1],
                'displayName': row[2],
                'firstConnectionDate': row[3],
                'lastActivityDate': row[4],
                'isActive': row[5],
                'email': row[6],
                'passwordResetRequired': row[7],
                'banned': row[8],
                'bannedDate': row[9],
                'bannedBy': row[10],
                'banReason': row[11],
                'role': row[12]
            }
        else:
            # If it's a dict-like object
            return {
                'id': row[0],
                'uuid': row[1],
                'displayName': row[2],
                'firstConnectionDate': row[3],
                'lastActivityDate': row[4],
                'isActive': row[5],
                'email': row[6],
                'passwordResetRequired': row[7],
                'banned': row[8],
                'bannedDate': row[9],
                'bannedBy': row[10],
                'banReason': row[11],
                'role': row[12]
            }
    else:
        # SQLite with row_factory
        return {
            'id': row['id'],
            'uuid': row['uuid'],
            'displayName': row['displayName'],
            'firstConnectionDate': row['firstConnectionDate'],
            'lastActivityDate': row['lastActivityDate'],
            'isActive': row['isActive'],
            'email': row['email'],
            'passwordResetRequired': row['passwordResetRequired'],
            'banned': row['banned'],
            'bannedDate': row['bannedDate'],
            'bannedBy': row['bannedBy'],
            'banReason': row['banReason'],
            'role': row['role']
        }

def get_user_by_uuid(uuid):
    """Get user by UUID from users database."""
    users_db = get_users_db()
    try:
        if USERS_DB_TYPE == 'postgresql':
            result = users_db.run(
                'SELECT * FROM users WHERE uuid = :uuid',
                uuid=uuid
            )
            if result:
                return result[0]
        else:
            cursor = users_db.cursor()
            cursor.execute('SELECT * FROM users WHERE uuid = ?', (uuid,))
            result = cursor.fetchone()
            if result:
                return result
        return None
    except Exception as e:
        app.logger.error(f'Error getting user by UUID: {str(e)}')
        return None

def get_user_by_email(email):
    """Get user by email from users database."""
    users_db = get_users_db()
    try:
        if USERS_DB_TYPE == 'postgresql':
            result = users_db.run(
                'SELECT * FROM users WHERE email = :email',
                email=email
            )
            if result:
                return result[0]
        else:
            cursor = users_db.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            result = cursor.fetchone()
            if result:
                return result
        return None
    except Exception as e:
        app.logger.error(f'Error getting user by email: {str(e)}')
        return None

def update_user_activity(uuid):
    """Update user's last activity date."""
    users_db = get_users_db()
    try:
        current_time = datetime.utcnow().isoformat()
        if USERS_DB_TYPE == 'postgresql':
            users_db.run('''
                UPDATE users 
                SET "lastActivityDate" = :activity_date 
                WHERE uuid = :uuid
            ''', uuid=uuid, activity_date=current_time)
        else:
            cursor = users_db.cursor()
            cursor.execute('''
                UPDATE users 
                SET lastActivityDate = ? 
                WHERE uuid = ?
            ''', (current_time, uuid))
            users_db.commit()
    except Exception as e:
        app.logger.error(f'Error updating user activity: {str(e)}')

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
        
        # Check if golf courses database is available
        if not golf_courses_db_available:
            app.logger.error('Search request failed - Golf courses database not available')
            return jsonify({
                'success': False,
                'error': 'Service temporarily unavailable - Database connection failed'
            }), 503
        
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
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'databases': {
                'golf_courses': 'connected' if golf_courses_db_available else 'disconnected',
                'users': 'connected' if users_db_available else 'disconnected'
            }
        }
        
        # Test golf courses database if available
        if golf_courses_db_available:
            try:
                db = get_db()
                if DB_TYPE == 'postgresql':
                    result = db.run('SELECT 1')
                else:
                    cursor = db.cursor()
                    cursor.execute('SELECT 1')
                    result = cursor.fetchone()
            except Exception as e:
                health_status['databases']['golf_courses'] = 'error'
                health_status['golf_courses_error'] = str(e)
        
        # Test users database if available
        if users_db_available:
            try:
                users_db = get_users_db()
                if USERS_DB_TYPE == 'postgresql':
                    result = users_db.run('SELECT 1')
                else:
                    cursor = users_db.cursor()
                    cursor.execute('SELECT 1')
                    result = cursor.fetchone()
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

# Test database connections on startup
golf_courses_db_available = False
users_db_available = False

# Test golf courses database connection
if test_golf_courses_db_connection():
    golf_courses_db_available = True
    try:
        # Try to get count if table exists
        db = get_db()
        if DB_TYPE == 'postgresql':
            result = db.run('SELECT COUNT(*) FROM golfcourse')
            course_count = result[0][0]
        else:
            cursor = db.cursor()
            cursor.execute('SELECT COUNT(*) FROM golfcourse')
            course_count = cursor.fetchone()[0]
        app.logger.info(f'Golf courses database ready - Total courses: {course_count}')
    except Exception as e:
        app.logger.warning(f'Golf courses database connected but table may not exist: {str(e)}')
        app.logger.info('Golf courses database connected (table creation required)')
else:
    app.logger.error('Golf courses database connection failed - API will not function properly')

# Test users database connection
if test_users_db_connection():
    users_db_available = True
    try:
        # Try to get count if table exists
        users_db = get_users_db()
        if USERS_DB_TYPE == 'postgresql':
            result = users_db.run('SELECT COUNT(*) FROM users')
            user_count = result[0][0]
        else:
            cursor = users_db.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
        app.logger.info(f'Users database ready - Total users: {user_count}')
    except Exception as e:
        app.logger.warning(f'Users database connected but table may not exist: {str(e)}')
        app.logger.info('Users database connected (table creation required)')
else:
    app.logger.error('Users database connection failed - User features will not be available')

# Log overall status
if golf_courses_db_available and users_db_available:
    app.logger.info('All database connections successful - API fully operational')
elif golf_courses_db_available:
    app.logger.warning('Only golf courses database available - User features disabled')
else:
    app.logger.error('Critical: No database connections available - API will not function')

if __name__ == '__main__':
    app.logger.info('Starting Flask development server')
    app.run(debug=True)
