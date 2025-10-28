#!/usr/bin/env python3

from flask import Flask, request, jsonify, g, redirect
import sqlite3
import math
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from urllib.parse import urlparse, parse_qs

# ============================================================================
# LOGGING CONFIGURATION - OVER THE TOP DIAGNOSTICS
# ============================================================================

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-25s | Line:%(lineno)-4d | %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('logs/app.log', mode='a'),
        logging.FileHandler('logs/app_debug.log', mode='a')
    ]
)

# Create specialized loggers
logger = logging.getLogger('GolfCourseAPI')
db_logger = logging.getLogger('Database')
auth_logger = logging.getLogger('Authentication')
api_logger = logging.getLogger('APIRequests')
error_logger = logging.getLogger('Errors')

# Set levels for specialized loggers
logger.setLevel(logging.DEBUG)
db_logger.setLevel(logging.DEBUG)
auth_logger.setLevel(logging.INFO)
api_logger.setLevel(logging.INFO)
error_logger.setLevel(logging.ERROR)

logger.info("=" * 80)
logger.info("Dewy Golf Flask app setup")
logger.info("=" * 80)

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Database configuration from environment variables
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///golfcourses.db')

logger.info(f"Database configuration loaded: {DATABASE_URL}")


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

def get_db_connection():
    
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




def check_database_health() -> Tuple[bool, Dict[str, Any]]:
    """
    Check database connection and verify golfcourse table exists and is accessible.
    
    Returns:
        Tuple of (is_healthy: bool, status_dict: Dict)
    """
    db_logger.info("Starting database health check...")
    health_status = {
        'database_connected': False,
        'golfcourse_table_exists': False,
        'golfcourse_table_accessible': False,
        'row_count': 0,
        'error': None
    }
    
    conn = None
    try:
        # Test connection
        db_logger.debug("Attempting database connection...")
        conn = get_db_connection()
        health_status['database_connected'] = True
        db_logger.info("✓ Database connection successful")
        
        # Check if golfcourse table exists
        db_logger.debug("Checking if golfcourse table exists...")
        result = conn.run("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'golfcourse'
            );
        """)
        table_exists = result[0][0] if result else False
        health_status['golfcourse_table_exists'] = table_exists
        
        if table_exists:
            db_logger.info("✓ golfcourse table exists")
            
            # Try to query the table
            db_logger.debug("Attempting to query golfcourse table...")
            result = conn.run("SELECT COUNT(*) as count FROM golfcourse;")
            row_count = result[0][0] if result else 0
            health_status['row_count'] = row_count
            health_status['golfcourse_table_accessible'] = True
            db_logger.info(f"✓ golfcourse table accessible with {row_count} rows")
        else:
            db_logger.warning("✗ golfcourse table does not exist")
        
        is_healthy = (health_status['database_connected'] and 
                     health_status['golfcourse_table_exists'] and 
                     health_status['golfcourse_table_accessible'])
        
        db_logger.info(f"Health check complete. Status: {'HEALTHY' if is_healthy else 'UNHEALTHY'}")
        return is_healthy, health_status
        
    except Exception as e:
        error_logger.error(f"✗ Database health check failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        health_status['error'] = str(e)
        return False, health_status
        
    finally:
        if conn:
            conn.close()
            db_logger.debug("Database connection closed")


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """
    Verify API key exists in users table and check if user is active and not banned.
    If API key doesn't exist, create a new user entry.
    
    Args:
        api_key: The API key to verify
        
    Returns:
        User dict if valid, None if invalid/banned/inactive
    """
    auth_logger.info(f"Verifying API key: {api_key[:8]}...")
    
    conn = None
    try:
        conn = get_db_connection()
        
        # Check if user exists
        auth_logger.debug(f"Querying users table for API key: {api_key[:8]}...")
        result = conn.run("""
            SELECT id, uuid, "displayName", "isActive", banned, 
                   "lastActivityDate", email, role
            FROM users 
            WHERE uuid = :uuid;
        """, uuid=api_key)
        
        if result:
            # Convert tuple result to dict
            columns = ['id', 'uuid', 'displayName', 'isActive', 'banned', 'lastActivityDate', 'email', 'role']
            user = dict(zip(columns, result[0]))
            
            auth_logger.info(f"✓ User found: id={user['id']}, displayName={user['displayName']}")
            
            # Check if user is banned
            if user['banned']:
                auth_logger.warning(f"✗ User {user['id']} is BANNED. Access denied.")
                conn.close()
                return None
            
            # Check if user is active
            if not user['isActive']:
                auth_logger.warning(f"✗ User {user['id']} is INACTIVE. Access denied.")
                conn.close()
                return None
            
            # Update last activity date
            auth_logger.debug(f"Updating lastActivityDate for user {user['id']}...")
            current_time = datetime.utcnow().isoformat()
            conn.run("""
                UPDATE users 
                SET "lastActivityDate" = :activity_date 
                WHERE id = :user_id;
            """, activity_date=current_time, user_id=user['id'])
            auth_logger.info(f"✓ User {user['id']} validated and activity updated")
            
            conn.close()
            return user
        else:
            # User doesn't exist, create new user
            auth_logger.info(f"User not found. Creating new user with API key: {api_key[:8]}...")
            
            current_time = datetime.utcnow().isoformat()
            result = conn.run("""
                INSERT INTO users (
                    uuid, "displayName", "firstConnectionDate", 
                    "isActive", "lastActivityDate"
                )
                VALUES (:uuid, :display_name, :first_conn, :is_active, :last_activity)
                RETURNING id, uuid, "displayName", "isActive", banned;
            """, uuid=api_key, display_name=f'User_{api_key[:8]}', 
                first_conn=current_time, is_active=True, last_activity=current_time)
            
            # Convert tuple result to dict
            columns = ['id', 'uuid', 'displayName', 'isActive', 'banned']
            new_user = dict(zip(columns, result[0]))
            
            auth_logger.info(f"✓ NEW USER CREATED: id={new_user['id']}, "
                           f"displayName={new_user['displayName']}")
            
            conn.close()
            return new_user
            
    except Exception as e:
        error_logger.error(f"✗ API key verification failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        if conn:
            conn.close()
        return None


def search_golf_courses(params: Dict[str, str]) -> Tuple[list, int]:
    """
    Search golf courses based on various parameters.
    
    Args:
        params: Dictionary of search parameters
        
    Returns:
        Tuple of (results: list, total_count: int)
    """
    api_logger.info(f"Searching golf courses with parameters: {params}")
    
    conn = None
    try:
        conn = get_db_connection()
        
        # Build dynamic query
        where_clauses = []
        query_params = {}
        
        # Name search (case-insensitive partial match)
        if 'name' in params and params['name']:
            where_clauses.append("name ILIKE :name")
            query_params['name'] = f"%{params['name']}%"
            api_logger.debug(f"Added name filter: ILIKE '%{params['name']}%'")
        
        # Address search (case-insensitive partial match)
        if 'address' in params and params['address']:
            where_clauses.append("address ILIKE :address")
            query_params['address'] = f"%{params['address']}%"
            api_logger.debug(f"Added address filter: ILIKE '%{params['address']}%'")
        
        # Phone search (exact match)
        if 'phone' in params and params['phone']:
            where_clauses.append("phone = :phone")
            query_params['phone'] = params['phone']
            api_logger.debug(f"Added phone filter: = '{params['phone']}'")
        
        # Website search (case-insensitive partial match)
        if 'website' in params and params['website']:
            where_clauses.append("website ILIKE :website")
            query_params['website'] = f"%{params['website']}%"
            api_logger.debug(f"Added website filter: ILIKE '%{params['website']}%'")
        
        # Timezone search (exact match)
        if 'timezone' in params and params['timezone']:
            where_clauses.append("timezone = :timezone")
            query_params['timezone'] = params['timezone']
            api_logger.debug(f"Added timezone filter: = '{params['timezone']}'")
        
        # UUID search (exact match)
        if 'uuid' in params and params['uuid']:
            where_clauses.append("uuid = :uuid")
            query_params['uuid'] = params['uuid']
            api_logger.debug(f"Added uuid filter: = '{params['uuid']}'")
        
        # Latitude/Longitude radius search
        if all(k in params for k in ['latitude', 'longitude', 'radius']):
            try:
                lat = float(params['latitude'])
                lon = float(params['longitude'])
                radius_km = float(params['radius'])
                
                # Using Haversine formula for distance calculation
                where_clauses.append("""
                    (6371 * acos(
                        cos(radians(:lat)) * cos(radians(latitude)) * 
                        cos(radians(longitude) - radians(:lon)) + 
                        sin(radians(:lat2)) * sin(radians(latitude))
                    )) <= :radius
                """)
                query_params['lat'] = lat
                query_params['lon'] = lon
                query_params['lat2'] = lat  # Used twice in formula
                query_params['radius'] = radius_km
                api_logger.debug(f"Added radius search: lat={lat}, lon={lon}, radius={radius_km}km")
            except ValueError as e:
                api_logger.warning(f"Invalid lat/lon/radius values: {e}")
        
        # Build final query
        base_query = "SELECT id, name, latitude, longitude, address, website, phone, timezone, uuid FROM golfcourse"
        if where_clauses:
            query = f"{base_query} WHERE {' AND '.join(where_clauses)}"
        else:
            query = base_query
        
        # Add pagination
        limit = min(int(params.get('limit', 100)), 1000)  # Max 1000 results
        offset = int(params.get('offset', 0))
        query += f" LIMIT :limit OFFSET :offset"
        query_params['limit'] = limit
        query_params['offset'] = offset
        
        api_logger.debug(f"Executing query: {query}")
        api_logger.debug(f"Query parameters: {query_params}")
        
        result = conn.run(query, **query_params)
        
        # Convert results to list of dicts
        columns = ['id', 'name', 'latitude', 'longitude', 'address', 'website', 'phone', 'timezone', 'uuid']
        results = [dict(zip(columns, row)) for row in result]
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM golfcourse"
        if where_clauses:
            count_params = {k: v for k, v in query_params.items() if k not in ['limit', 'offset']}
            count_query += f" WHERE {' AND '.join(where_clauses)}"
            count_result = conn.run(count_query, **count_params)
        else:
            count_result = conn.run(count_query)
        
        total_count = count_result[0][0] if count_result else 0
        
        conn.close()
        
        api_logger.info(f"✓ Search completed: {len(results)} results returned, "
                       f"{total_count} total matches")
        
        return results, total_count
        
    except Exception as e:
        error_logger.error(f"✗ Golf course search failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        if conn:
            conn.close()
        raise


# ============================================================================
# DECORATORS
# ============================================================================

def require_api_key(f):
    """Decorator to require and validate API key for protected endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request_id = str(uuid_lib.uuid4())[:8]
        api_logger.info(f"[{request_id}] Request to {request.path} from {request.remote_addr}")
        
        # Get API key from header
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
        
        if not api_key:
            auth_logger.warning(f"[{request_id}] ✗ Missing API key in request")
            return jsonify({
                'error': 'Missing API key',
                'message': 'Please provide API key in X-API-Key or Authorization header'
            }), 401
        
        # Remove 'Bearer ' prefix if present
        if api_key.startswith('Bearer '):
            api_key = api_key[7:]
        
        auth_logger.debug(f"[{request_id}] Validating API key: {api_key[:8]}...")
        
        # Verify API key
        user = verify_api_key(api_key)
        
        if not user:
            auth_logger.warning(f"[{request_id}] ✗ Invalid, inactive, or banned API key")
            return jsonify({
                'error': 'Invalid API key',
                'message': 'API key is invalid, inactive, or banned'
            }), 403
        
        auth_logger.info(f"[{request_id}] ✓ API key validated for user: {user['id']}")
        
        # Add user info to request context
        request.user = user
        request.request_id = request_id
        
        return f(*args, **kwargs)
    
    return decorated_function


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint that verifies database and golfcourse table status."""
    request_id = str(uuid_lib.uuid4())[:8]
    api_logger.info(f"[{request_id}] Health check requested from {request.remote_addr}")
    
    is_healthy, status = check_database_health()
    
    response_data = {
        'status': 'healthy' if is_healthy else 'unhealthy',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': status
    }
    
    status_code = 200 if is_healthy else 503
    
    api_logger.info(f"[{request_id}] Health check complete: "
                   f"{'HEALTHY' if is_healthy else 'UNHEALTHY'} (HTTP {status_code})")
    
    return jsonify(response_data), status_code


@app.route('/search', methods=['GET'])
@require_api_key
def search():
    """Search golf courses endpoint (requires valid API key)."""
    request_id = request.request_id
    user = request.user
    
    api_logger.info(f"[{request_id}] Search initiated by user {user['id']} "
                   f"({user['displayName']})")
    
    try:
        # Get search parameters
        params = request.args.to_dict()
        api_logger.debug(f"[{request_id}] Search parameters: {params}")
        
        # Perform search
        results, total_count = search_golf_courses(params)
        
        response_data = {
            'success': True,
            'count': len(results),
            'total': total_count,
            'limit': int(params.get('limit', 100)),
            'offset': int(params.get('offset', 0)),
            'results': results
        }
        
        api_logger.info(f"[{request_id}] ✓ Search successful: {len(results)} results returned")
        
        return jsonify(response_data), 200
        
    except Exception as e:
        error_logger.error(f"[{request_id}] ✗ Search failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        
        return jsonify({
            'success': False,
            'error': 'Search failed',
            'message': str(e)
        }), 500


@app.route('/', methods=['GET'])
def root():
    """Root endpoint with API information."""
    api_logger.info(f"Root endpoint accessed from {request.remote_addr}")
    
    return jsonify({
        'service': 'Golf Course Search API',
        'version': '1.0.0',
        'endpoints': {
            '/health': 'Health check endpoint (no auth required)',
            '/search': 'Search golf courses (requires API key)',
        },
        'authentication': 'Provide API key in X-API-Key or Authorization header'
    }), 200


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    error_logger.warning(f"404 Not Found: {request.path} from {request.remote_addr}")
    return jsonify({
        'error': 'Not Found',
        'message': f'The requested URL {request.path} was not found'
    }), 404


@app.errorhandler(405)
def method_not_allowed(e):
    error_logger.warning(f"405 Method Not Allowed: {request.method} {request.path} "
                        f"from {request.remote_addr}")
    return jsonify({
        'error': 'Method Not Allowed',
        'message': f'The method {request.method} is not allowed for {request.path}'
    }), 405


@app.errorhandler(500)
def internal_error(e):
    error_logger.error(f"500 Internal Server Error: {str(e)}")
    error_logger.error(traceback.format_exc())
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

def main():
    """Main application entry point."""
    logger.info("Initializing Golf Course Search API...")
    
    # Test database connection
    try:
        db_logger.info("Testing database connection...")
        test_conn = get_db_connection()
        test_conn.close()
        db_logger.info("✓ Database connection test successful")
    except Exception as e:
        error_logger.critical(f"✗ Database connection test failed: {str(e)}")
        error_logger.critical("Please check your database configuration")
        sys.exit(1)
    
    # SSL Configuration
    ssl_enabled = os.getenv('SSL_ENABLED', 'false').lower() == 'true'
    ssl_cert = os.getenv('SSL_CERT_PATH', '/etc/ssl/certs/cert.pem')
    ssl_key = os.getenv('SSL_KEY_PATH', '/etc/ssl/private/key.pem')
    
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', '5000'))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Server configuration:")
    logger.info(f"  Host: {host}")
    logger.info(f"  Port: {port}")
    logger.info(f"  SSL Enabled: {ssl_enabled}")
    logger.info(f"  Debug Mode: {debug}")
    
    if ssl_enabled:
        if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            logger.info(f"  SSL Certificate: {ssl_cert}")
            logger.info(f"  SSL Key: {ssl_key}")
            logger.info("=" * 80)
            logger.info("🚀 Starting server with SSL...")
            app.run(
                host=host,
                port=port,
                debug=debug,
                ssl_context=(ssl_cert, ssl_key)
            )
        else:
            error_logger.critical(f"SSL enabled but certificate files not found!")
            error_logger.critical(f"  Expected cert: {ssl_cert}")
            error_logger.critical(f"  Expected key: {ssl_key}")
            logger.info("=" * 80)
            logger.warning("⚠️  Starting server WITHOUT SSL...")
            app.run(host=host, port=port, debug=debug)
    else:
        logger.info("=" * 80)
        logger.info("🚀 Starting server WITHOUT SSL...")
        app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 80)
        logger.info("Received shutdown signal (Ctrl+C)")
        logger.info("Shutting down gracefully...")
        logger.info("✓ Application shutdown complete")
        logger.info("=" * 80)
    except Exception as e:
        error_logger.critical(f"Fatal error during startup: {str(e)}")
        error_logger.critical(traceback.format_exc())
        sys.exit(1)