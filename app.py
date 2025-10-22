from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
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
database_url = os.environ.get('DATABASE_URL', 'sqlite:///golfcourses.db')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.logger.info(f'Configuring database connection: {database_url}')

db = SQLAlchemy(app)

# Golf Course Model
class GolfCourse(db.Model):
    __tablename__ = 'golfcourse'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    latitude = db.Column(db.Numeric, nullable=False)
    longitude = db.Column(db.Numeric, nullable=False)
    address = db.Column(db.Text)
    website = db.Column(db.Text)
    phone = db.Column(db.Text)
    timezone = db.Column(db.Text)
    uuid = db.Column(db.Text, default='constant')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'latitude': float(self.latitude),
            'longitude': float(self.longitude),
            'address': self.address,
            'website': self.website,
            'phone': self.phone,
            'timezone': self.timezone,
            'uuid': self.uuid
        }

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
        
        query = GolfCourse.query
        
        # Search by latitude/longitude (nearest courses)
        if lat and lng:
            try:
                lat = float(lat)
                lng = float(lng)
                
                app.logger.info(f'Performing location-based search at coordinates: ({lat}, {lng})')
                
                # Get all courses and calculate distances
                app.logger.info('Querying database for all golf courses')
                courses = query.all()
                app.logger.info(f'Retrieved {len(courses)} courses from database')
                
                courses_with_distance = []
                
                for course in courses:
                    distance = calculate_distance(
                        lat, lng, 
                        float(course.latitude), 
                        float(course.longitude)
                    )
                    course_dict = course.to_dict()
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
            query = query.filter(
                or_(
                    GolfCourse.address.ilike(f'%{city}%'),
                    GolfCourse.name.ilike(f'%{city}%')
                )
            )
            results = query.limit(limit).all()
            
            app.logger.info(f'City search completed - Found {len(results)} courses matching "{city}"')
            if results:
                app.logger.info(f'Sample results: {[course.name for course in results[:3]]}')
            
            return jsonify({
                'success': True,
                'search_type': 'city',
                'search_term': city,
                'results': [course.to_dict() for course in results],
                'total_found': len(results)
            })
        
        # Search by zipcode
        elif zipcode:
            app.logger.info(f'Performing zipcode-based search for: {zipcode}')
            query = query.filter(GolfCourse.address.ilike(f'%{zipcode}%'))
            results = query.limit(limit).all()
            
            app.logger.info(f'Zipcode search completed - Found {len(results)} courses matching "{zipcode}"')
            if results:
                app.logger.info(f'Sample results: {[course.name for course in results[:3]]}')
            
            return jsonify({
                'success': True,
                'search_type': 'zipcode',
                'search_term': zipcode,
                'results': [course.to_dict() for course in results],
                'total_found': len(results)
            })
        
        # Search by course name
        elif name:
            app.logger.info(f'Performing name-based search for: {name}')
            query = query.filter(GolfCourse.name.ilike(f'%{name}%'))
            results = query.limit(limit).all()
            
            app.logger.info(f'Name search completed - Found {len(results)} courses matching "{name}"')
            if results:
                app.logger.info(f'Sample results: {[course.name for course in results[:3]]}')
            
            return jsonify({
                'success': True,
                'search_type': 'name',
                'search_term': name,
                'results': [course.to_dict() for course in results],
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

# Create database tables
try:
    with app.app_context():
        app.logger.info('Attempting to create database tables')
        db.create_all()
        
        # Log database connection test
        try:
            course_count = GolfCourse.query.count()
            app.logger.info(f'Database connection successful - Total courses in database: {course_count}')
        except Exception as e:
            app.logger.error(f'Database connection test failed: {str(e)}', exc_info=True)
            
except Exception as e:
    app.logger.error(f'Failed to initialize database: {str(e)}', exc_info=True)

if __name__ == '__main__':
    app.logger.info('Starting Flask development server')
    app.run(debug=True)
