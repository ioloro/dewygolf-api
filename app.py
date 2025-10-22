from flask import Flask, request, jsonify, g
import sqlite3
import math
import os
import logging
from logging.handlers import RotatingFileHandler
import sys

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
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///golfcourses.db')
app.logger.info(f'Configuring database connection: {DATABASE_URL}')

# Parse DATABASE_URL to determine database type and path
if DATABASE_URL.startswith('sqlite'):
    # Handle SQLite URLs (sqlite:///path or sqlite://path)
    DATABASE = DATABASE_URL.replace('sqlite:///', '').replace('sqlite://', '')
    DB_TYPE = 'sqlite'
    app.logger.info(f'Using SQLite database: {DATABASE}')
elif DATABASE_URL.startswith('postgresql') or DATABASE_URL.startswith('postgres'):
    # PostgreSQL connection - will need psycopg2
    DATABASE = DATABASE_URL
    DB_TYPE = 'postgresql'
    app.logger.info('Using PostgreSQL database')
else:
    # Default to SQLite if format is unclear
    DATABASE = DATABASE_URL if DATABASE_URL else 'golfcourses.db'
    DB_TYPE = 'sqlite'
    app.logger.info(f'Using SQLite database (default): {DATABASE}')

def get_db():
    """Get database connection for the current request."""
    db = getattr(g, '_database', None)
    if db is None:
        if DB_TYPE == 'postgresql':
            try:
                import psycopg2
                import psycopg2.extras
                db = g._database = psycopg2.connect(DATABASE)
                app.logger.info('PostgreSQL connection established')
            except ImportError:
                app.logger.error('psycopg2 not installed. Install with: pip install psycopg2-binary')
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

def init_db():
    """Initialize the database with required tables."""
    try:
        if DB_TYPE == 'postgresql':
            import psycopg2
            conn = psycopg2.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
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
            
            conn.commit()
            conn.close()
            app.logger.info('PostgreSQL database tables created successfully')
        else:
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
        # PostgreSQL returns tuples, need to map by index
        # Assuming columns are: id, name, latitude, longitude, address, website, phone, timezone, uuid
        return {
            'id': row[0],
            'name': row[1],
            'latitude': float(row[2]),
            'longitude': float(row[3]),
            'address': row[4],
            'website': row[5],
            'phone': row[6],
            'timezone': row[7],
            'uuid': row[8]
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

def get_row_value(row, column_name, index):
    """Get value from row - works with both SQLite Row objects and PostgreSQL tuples."""
    if DB_TYPE == 'postgresql':
        return row[index]
    else:
        return row[column_name]

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
def hello_world():
    app.logger.info('Root endpoint accessed')
    return "Golf Course Search API - Use /search endpoint"

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
        cursor = db.cursor()
        
        # Search by latitude/longitude (nearest courses)
        if lat and lng:
            try:
                lat = float(lat)
                lng = float(lng)
                
                app.logger.info(f'Performing location-based search at coordinates: ({lat}, {lng})')
                
                # Get all courses and calculate distances
                app.logger.info('Querying database for all golf courses')
                cursor.execute('SELECT * FROM golfcourse')
                courses = cursor.fetchall()
                app.logger.info(f'Retrieved {len(courses)} courses from database')
                
                courses_with_distance = []
                
                for course in courses:
                    distance = calculate_distance(
                        lat, lng, 
                        float(get_row_value(course, 'latitude', 2)), 
                        float(get_row_value(course, 'longitude', 3))
                    )
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
            
            if DB_TYPE == 'postgresql':
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address ILIKE %s OR name ILIKE %s
                    LIMIT %s
                ''', (f'%{city}%', f'%{city}%', limit))
            else:
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address LIKE ? OR name LIKE ?
                    LIMIT ?
                ''', (f'%{city}%', f'%{city}%', limit))
            
            results = cursor.fetchall()
            
            app.logger.info(f'City search completed - Found {len(results)} courses matching "{city}"')
            if results:
                sample_names = [get_row_value(row, 'name', 1) for row in results[:3]]
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
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address ILIKE %s
                    LIMIT %s
                ''', (f'%{zipcode}%', limit))
            else:
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE address LIKE ?
                    LIMIT ?
                ''', (f'%{zipcode}%', limit))
            
            results = cursor.fetchall()
            
            app.logger.info(f'Zipcode search completed - Found {len(results)} courses matching "{zipcode}"')
            if results:
                sample_names = [get_row_value(row, 'name', 1) for row in results[:3]]
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
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE name ILIKE %s
                    LIMIT %s
                ''', (f'%{name}%', limit))
            else:
                cursor.execute('''
                    SELECT * FROM golfcourse 
                    WHERE name LIKE ?
                    LIMIT ?
                ''', (f'%{name}%', limit))
            
            results = cursor.fetchall()
            
            app.logger.info(f'Name search completed - Found {len(results)} courses matching "{name}"')
            if results:
                sample_names = [get_row_value(row, 'name', 1) for row in results[:3]]
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

# Initialize database on startup
if init_db():
    try:
        if DB_TYPE == 'postgresql':
            import psycopg2
            conn = psycopg2.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM golfcourse')
            course_count = cursor.fetchone()[0]
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
