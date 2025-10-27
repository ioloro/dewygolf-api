#!/usr/bin/env python3
"""
Golf Course Search API
A production-ready Flask application with SSL, database health checks, 
and API key authentication for searching golf courses.
"""

import os
import logging
import sys
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import pool
from flask import Flask, request, jsonify, Response
from functools import wraps
import traceback
import uuid as uuid_lib

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
logger.info("Golf Course API Application Starting")
logger.info("=" * 80)

# ============================================================================
# FLASK APPLICATION SETUP
# ============================================================================

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Database configuration from environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'golf_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', ''),
}

logger.info(f"Database configuration loaded: host={DB_CONFIG['host']}, "
            f"port={DB_CONFIG['port']}, database={DB_CONFIG['database']}, "
            f"user={DB_CONFIG['user']}")

# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

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
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if golfcourse table exists
        db_logger.debug("Checking if golfcourse table exists...")
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'golfcourse'
            );
        """)
        table_exists = cursor.fetchone()['exists']
        health_status['golfcourse_table_exists'] = table_exists
        
        if table_exists:
            db_logger.info("✓ golfcourse table exists")
            
            # Try to query the table
            db_logger.debug("Attempting to query golfcourse table...")
            cursor.execute("SELECT COUNT(*) as count FROM golfcourse;")
            result = cursor.fetchone()
            health_status['row_count'] = result['count']
            health_status['golfcourse_table_accessible'] = True
            db_logger.info(f"✓ golfcourse table accessible with {result['count']} rows")
        else:
            db_logger.warning("✗ golfcourse table does not exist")
        
        cursor.close()
        
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
            return_db_connection(conn)


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
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if user exists
        auth_logger.debug(f"Querying users table for API key: {api_key[:8]}...")
        cursor.execute("""
            SELECT id, uuid, "displayName", "isActive", banned, 
                   "lastActivityDate", email, role
            FROM users 
            WHERE uuid = %s;
        """, (api_key,))
        
        user = cursor.fetchone()
        
        if user:
            auth_logger.info(f"✓ User found: id={user['id']}, displayName={user['displayName']}")
            
            # Check if user is banned
            if user['banned']:
                auth_logger.warning(f"✗ User {user['id']} is BANNED. Access denied.")
                cursor.close()
                return None
            
            # Check if user is active
            if not user['isActive']:
                auth_logger.warning(f"✗ User {user['id']} is INACTIVE. Access denied.")
                cursor.close()
                return None
            
            # Update last activity date
            auth_logger.debug(f"Updating lastActivityDate for user {user['id']}...")
            current_time = datetime.utcnow().isoformat()
            cursor.execute("""
                UPDATE users 
                SET "lastActivityDate" = %s 
                WHERE id = %s;
            """, (current_time, user['id']))
            conn.commit()
            auth_logger.info(f"✓ User {user['id']} validated and activity updated")
            
            cursor.close()
            return dict(user)
        else:
            # User doesn't exist, create new user
            auth_logger.info(f"User not found. Creating new user with API key: {api_key[:8]}...")
            
            current_time = datetime.utcnow().isoformat()
            cursor.execute("""
                INSERT INTO users (
                    uuid, "displayName", "firstConnectionDate", 
                    "isActive", "lastActivityDate"
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, uuid, "displayName", "isActive", banned;
            """, (api_key, f'User_{api_key[:8]}', current_time, True, current_time))
            
            new_user = cursor.fetchone()
            conn.commit()
            
            auth_logger.info(f"✓ NEW USER CREATED: id={new_user['id']}, "
                           f"displayName={new_user['displayName']}")
            
            cursor.close()
            return dict(new_user)
            
    except Exception as e:
        error_logger.error(f"✗ API key verification failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        if conn:
            conn.rollback()
        return None
        
    finally:
        if conn:
            return_db_connection(conn)


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
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Build dynamic query
        where_clauses = []
        query_params = []
        param_counter = 1
        
        # Name search (case-insensitive partial match)
        if 'name' in params and params['name']:
            where_clauses.append(f"name ILIKE ${param_counter}")
            query_params.append(f"%{params['name']}%")
            param_counter += 1
            api_logger.debug(f"Added name filter: ILIKE '%{params['name']}%'")
        
        # Address search (case-insensitive partial match)
        if 'address' in params and params['address']:
            where_clauses.append(f"address ILIKE ${param_counter}")
            query_params.append(f"%{params['address']}%")
            param_counter += 1
            api_logger.debug(f"Added address filter: ILIKE '%{params['address']}%'")
        
        # Phone search (exact match)
        if 'phone' in params and params['phone']:
            where_clauses.append(f"phone = ${param_counter}")
            query_params.append(params['phone'])
            param_counter += 1
            api_logger.debug(f"Added phone filter: = '{params['phone']}'")
        
        # Website search (case-insensitive partial match)
        if 'website' in params and params['website']:
            where_clauses.append(f"website ILIKE ${param_counter}")
            query_params.append(f"%{params['website']}%")
            param_counter += 1
            api_logger.debug(f"Added website filter: ILIKE '%{params['website']}%'")
        
        # Timezone search (exact match)
        if 'timezone' in params and params['timezone']:
            where_clauses.append(f"timezone = ${param_counter}")
            query_params.append(params['timezone'])
            param_counter += 1
            api_logger.debug(f"Added timezone filter: = '{params['timezone']}'")
        
        # UUID search (exact match)
        if 'uuid' in params and params['uuid']:
            where_clauses.append(f"uuid = ${param_counter}")
            query_params.append(params['uuid'])
            param_counter += 1
            api_logger.debug(f"Added uuid filter: = '{params['uuid']}'")
        
        # Latitude/Longitude radius search
        if all(k in params for k in ['latitude', 'longitude', 'radius']):
            try:
                lat = float(params['latitude'])
                lon = float(params['longitude'])
                radius_km = float(params['radius'])
                
                # Using Haversine formula for distance calculation
                where_clauses.append(f"""
                    (6371 * acos(
                        cos(radians(${param_counter})) * cos(radians(latitude)) * 
                        cos(radians(longitude) - radians(${param_counter + 1})) + 
                        sin(radians(${param_counter})) * sin(radians(latitude))
                    )) <= ${param_counter + 2}
                """)
                query_params.extend([lat, lon, radius_km])
                param_counter += 3
                api_logger.debug(f"Added radius search: lat={lat}, lon={lon}, radius={radius_km}km")
            except ValueError as e:
                api_logger.warning(f"Invalid lat/lon/radius values: {e}")
        
        # Build final query
        base_query = "SELECT * FROM golfcourse"
        if where_clauses:
            # Convert $1, $2 format to %s for psycopg2
            where_sql = " AND ".join(where_clauses)
            where_sql = where_sql.replace('$', '%s_').replace('%s_', '%s', 100)
            for i in range(len(query_params), 0, -1):
                where_sql = where_sql.replace(f'%s', '%s', 1)
            query = f"{base_query} WHERE {where_sql}"
        else:
            query = base_query
        
        # Add pagination
        limit = min(int(params.get('limit', 100)), 1000)  # Max 1000 results
        offset = int(params.get('offset', 0))
        query += f" LIMIT {limit} OFFSET {offset}"
        
        api_logger.debug(f"Executing query: {query}")
        api_logger.debug(f"Query parameters: {query_params}")
        
        cursor.execute(query, query_params)
        results = cursor.fetchall()
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM golfcourse"
        if where_clauses:
            where_sql = " AND ".join(where_clauses)
            where_sql = where_sql.replace('$', '%s_').replace('%s_', '%s', 100)
            for i in range(len(query_params), 0, -1):
                where_sql = where_sql.replace(f'%s', '%s', 1)
            count_query += f" WHERE {where_sql}"
        
        cursor.execute(count_query, query_params)
        total_count = cursor.fetchone()['total']
        
        cursor.close()
        
        api_logger.info(f"✓ Search completed: {len(results)} results returned, "
                       f"{total_count} total matches")
        
        return [dict(row) for row in results], total_count
        
    except Exception as e:
        error_logger.error(f"✗ Golf course search failed: {str(e)}")
        error_logger.error(traceback.format_exc())
        raise
        
    finally:
        if conn:
            return_db_connection(conn)


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
    
    # Initialize database connection pool
    if not initialize_connection_pool():
        logger.critical("Failed to initialize database connection pool. Exiting.")
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
        if connection_pool:
            connection_pool.closeall()
            logger.info("✓ Database connection pool closed")
        logger.info("✓ Application shutdown complete")
        logger.info("=" * 80)
    except Exception as e:
        error_logger.critical(f"Fatal error during startup: {str(e)}")
        error_logger.critical(traceback.format_exc())
        sys.exit(1)