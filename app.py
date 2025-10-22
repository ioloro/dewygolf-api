from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import math
import os

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///golfcourses.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    try:
        # Get parameters from query string or JSON body
        if request.method == 'POST':
            data = request.get_json() or {}
        else:
            data = request.args.to_dict()
        
        lat = data.get('lat')
        lng = data.get('lng')
        city = data.get('city')
        zipcode = data.get('zipcode')
        name = data.get('name')
        limit = int(data.get('limit', 10))
        
        query = GolfCourse.query
        
        # Search by latitude/longitude (nearest courses)
        if lat and lng:
            try:
                lat = float(lat)
                lng = float(lng)
                
                # Get all courses and calculate distances
                courses = query.all()
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
                
                return jsonify({
                    'success': True,
                    'search_type': 'location',
                    'coordinates': {'lat': lat, 'lng': lng},
                    'results': results,
                    'total_found': len(results)
                })
                
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid latitude or longitude values'
                }), 400
        
        # Search by city name
        elif city:
            query = query.filter(
                or_(
                    GolfCourse.address.ilike(f'%{city}%'),
                    GolfCourse.name.ilike(f'%{city}%')
                )
            )
            results = query.limit(limit).all()
            
            return jsonify({
                'success': True,
                'search_type': 'city',
                'search_term': city,
                'results': [course.to_dict() for course in results],
                'total_found': len(results)
            })
        
        # Search by zipcode
        elif zipcode:
            query = query.filter(GolfCourse.address.ilike(f'%{zipcode}%'))
            results = query.limit(limit).all()
            
            return jsonify({
                'success': True,
                'search_type': 'zipcode',
                'search_term': zipcode,
                'results': [course.to_dict() for course in results],
                'total_found': len(results)
            })
        
        # Search by course name
        elif name:
            query = query.filter(GolfCourse.name.ilike(f'%{name}%'))
            results = query.limit(limit).all()
            
            return jsonify({
                'success': True,
                'search_type': 'name',
                'search_term': name,
                'results': [course.to_dict() for course in results],
                'total_found': len(results)
            })
        
        else:
            return jsonify({
                'success': False,
                'error': 'Please provide one of: lat/lng, city, zipcode, or name'
            }), 400
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Create database tables
with app.app_context():
    db.create_all()
