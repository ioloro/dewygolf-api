from flask import Flask, request, jsonify, g, redirect
import sqlite3
import math
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

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
DATABASE_URL = os.environ.get('DATABASE_URL')
app.logger.info(f'DATABASE_URL: {DATABASE_URL}')
DATABASE = DATABASE_URL
app.logger.info('Using PostgreSQL database with pg8000')


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
def close_connection(exception):
    """Close database connection at the end of request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        app.logger.debug('Database connection closed')

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

@app.route("/")
def root_route():
    return redirect("https://www.dewygolf.com", code=302)

@app.route("/search", methods=['GET', 'POST'])
def search_courses():
    """
    Search for golf courses by various criteria:
    - lat/lng: Find nearest courses
    - city: Search by city name
    - zipcode: Search by zipcode
    - name: Search by course name
    - limit: Number of results to return (default: 10)
    """
    request_id = request.headers.get('X-Request-ID', 'N/A')
    client_ip = request.remote_addr
    
    app.logger.info(f'Search request received - Method: {request.method}, IP: {client_ip}, Request-ID: {request_id}')
    
    try:
        # Get parameters from query string or JSON body
        if request.method == 'POST':
            data = request.get_json() or {}
            app.logger.info(f'POST request with JSON body: {data}')
        else:
            data = request.args.to_dict()
            app.logger.info(f'GET request with query params: {data}')
        
        lat = data.get('lat')
        lng = data.get('lng')
        city = data.get('city')
        zipcode = data.get('zipcode')
        name = data.get('name')
        limit = int(data.get('limit', 10))
        
        app.logger.info(f'Search parameters - lat: {lat}, lng: {lng}, city: {city}, zipcode: {zipcode}, name: {name}, limit: {limit}')
        
        db = get_db()
        
        # Search by latitude/longitude (nearest courses)
        if lat and lng:
            try:
                lat = float(lat)
                lng = float(lng)
                
                app.logger.info(f'Performing location-based search at coordinates: ({lat}, {lng})')
                
                # Get all courses and calculate distances
                app.logger.info('Querying database for all golf courses')
                
                courses = db.run('SELECT * FROM golfcourse')
                
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
                
            except ValueError as ve:
                app.logger.error(f'Invalid coordinate values - lat: {lat}, lng: {lng}, error: {str(ve)}')
                return jsonify({
                    'success': False,
                    'error': 'Invalid latitude or longitude values'
                }), 400
        
        # Search by city name
        elif city:
            app.logger.info(f'Performing city-based search for: {city}')
            
            results = db.run(
                'SELECT * FROM golfcourse WHERE address ILIKE :pattern OR name ILIKE :pattern LIMIT :limit',
                pattern=f'%{city}%',
                limit=limit
            )
            
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
            
            results = db.run(
                'SELECT * FROM golfcourse WHERE address ILIKE :pattern LIMIT :limit',
                pattern=f'%{zipcode}%',
                limit=limit
            )
            
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
            
            results = db.run(
                'SELECT * FROM golfcourse WHERE name ILIKE :pattern LIMIT :limit',
                pattern=f'%{name}%',
                limit=limit
            )
            
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
            app.logger.warning(f'Search request missing required parameters - Provided data: {data}')
            return jsonify({
                'success': False,
                'error': 'Please provide one of: lat/lng, city, zipcode, or name'
            }), 400
            
    except Exception as e:
        app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/authenticate", methods=['GET', 'POST'])
def authenticate():
    """
    Recieve user information or create a new user
    """
    request_id = request.headers.get('X-Request-ID', 'N/A')
    client_ip = request.remote_addr
    
    app.logger.info(f'Authenticate request received - Method: {request.method}, IP: {client_ip}, Request-ID: {request_id}')
    
    try:
        # Get parameters from query string or JSON body
        if request.method == 'POST':
            data = request.get_json() or {}
            app.logger.info(f'POST request with JSON body: {data}')
        else:
            data = request.args.to_dict()
            app.logger.info(f'GET request with query params: {data}')

        apiKey = data.get('apiKey')
        limit = int(data.get('limit', 1))
        
        app.logger.info(f'apiKey parameters - apiKey {apiKey}')
        
        db = get_db()

        if apiKey:
            app.logger.info(f'Performing apiKey search for: {apiKey}')
            
            results = db.run(
                'SELECT * FROM users WHERE uuid ILIKE :pattern LIMIT :limit',
                pattern=f'%{apiKey}%',
                limit=limit
            )
            
            app.logger.info(f'apiKey search completed - Found {len(results)} users matching "{apiKey}"')
            if results:
                sample_names = [get_row_value(row, 1) for row in results[:3]]
                app.logger.info(f'Sample results: {sample_names}')
            
            return jsonify({
                'success': True,
                'search_type': 'apiKey',
                'search_term': apiKey,
                'results': [user_to_dict(row) for row in results],
                'total_found': len(results)
            })
        
        else:
            app.logger.warning(f'Authenticate request missing required parameters - Provided data: {data}')
            return jsonify({
                'success': False,
                'error': 'Please provide an apiKey'
            }), 400
            
    except Exception as e:
        app.logger.error(f'Unexpected error in search endpoint: {str(e)}', exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Initialize database on startup
if init_db():
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

    except Exception as e:
        app.logger.error(f'Database connection test failed: {str(e)}', exc_info=True)

if __name__ == '__main__':
    app.logger.info('Starting Flask development server')
    app.run(debug=True)
