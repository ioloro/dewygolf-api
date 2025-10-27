from flask import Flask, request, jsonify, g
from flask_cors import CORS
import pg8000.native
from urllib.parse import urlparse, parse_qs
import os
from datetime import datetime
from functools import wraps
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Database configuration
USERS_DATABASE = os.environ.get('DATABASE_URL', 'postgresql://user:pass@localhost:5432/defaultdb')

# Security event logging
def log_security_event(event_type, details):
    """Log security-related events."""
    app.logger.warning(f'SECURITY EVENT - {event_type}: {details}')

def get_users_db():
    """Get users database connection for the current request."""
    app.logger.debug('get_users_db() called - checking for existing connection')
    
    users_db = getattr(g, '_users_database', None)
    
    if users_db is None:
        app.logger.info('No existing database connection found in request context - creating new connection')
        
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
        app.logger.debug('Reusing existing database connection from request context')
        app.logger.debug(f'Connection type: {type(users_db)}')
    
    app.logger.debug('get_users_db() returning connection')
    return users_db


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
        
        try:
            app.logger.debug('Attempting to get database connection')
            users_db = get_users_db()
            app.logger.debug(f'Database connection obtained: {type(users_db)}')
            
            # Check if API key exists in database
            app.logger.debug(f'Querying database for API key {masked_key}')
            
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


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection at the end of request."""
    app.logger.debug('teardown_appcontext called - closing database connections')
    
    users_db = getattr(g, '_users_database', None)
    if users_db is not None:
        app.logger.debug('Closing users database connection')
        try:
            users_db.close()
            app.logger.debug('Users database connection closed successfully')
        except Exception as e:
            app.logger.error(f'Error closing users database connection: {str(e)}', exc_info=True)


# Example API endpoint
@app.route('/api/test', methods=['GET'])
@require_api_key
def test_endpoint():
    """Test endpoint to verify API key authentication."""
    app.logger.info(f'Test endpoint accessed from {request.remote_addr}')
    return jsonify({'message': 'API key authentication successful', 'timestamp': datetime.utcnow().isoformat()})


if __name__ == '__main__':
    app.logger.info('Starting Flask application')
    app.logger.info(f'Database URL: {USERS_DATABASE[:30]}...[REDACTED]')
    app.run(debug=True, host='0.0.0.0', port=5000)