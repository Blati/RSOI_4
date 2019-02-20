from services import root_dir, nice_json
from flask import Flask
from flask import request
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
from werkzeug.exceptions import NotFound, ServiceUnavailable
from datetime import datetime
import json
import requests
from logging import FileHandler, WARNING

app = Flask(__name__)

app.config['MONGO_DBNAME'] = 'authusers'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/authusers'
app.config['JWT_SECRET_KEY'] = 'definetly_not_a_secret_key'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

CORS(app)

with open("{}/database/users.json".format(root_dir()), "r") as f:
    users = json.load(f)
	
@app.route("/", methods=['GET'])
def hello():
    return nice_json({
        "uri": "/",
        "subresource_uris": {
            "users": "/users",
            "user": "/users/<username>",
			"auth": "/auth/login",
			"auth_reg": "/auth/register",
            "bookings": "/users/<username>/bookings",
            "bookings_add": "/users/<username>/bookings/add"
        }
    })

@app.route("/users", methods=['GET'])
def users_list():
    return nice_json(users)

@app.route("/auth/register", methods=['POST'])
def user_register():
    auth = mongo.db.auth
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.utcnow()

    user_id = auth.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password, 
	'created' : created, 
	})
    new_user = auth.find_one({'_id' : user_id})

    result = {'result' : {'email' : new_user['email'] + ' registered'}}

    return nice_json(result)
	
@app.route("/auth/login", methods=['POST'])
def user_login():
    auth = mongo.db.auth
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = auth.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'first_name': response['first_name'],
				'last_name': response['last_name'],
				'email': response['email']}
				)
            result = access_token
        else:
            result = nice_json({"error":"Invalid username and password"})            
    else:
        result = nice_json({"result":"No results found"})

    return result
	
@app.route("/users/<username>", methods=['GET'])
def user_record(username):
    if username not in users:
        raise NotFound

    return nice_json(users[username])

@app.route("/users/<username>/bookings", methods=['GET'])
def user_bookings(username):
    """
    Gets booking information from the 'Bookings Service' for the user, and
     movie ratings etc. from the 'Movie Service' and returns a list.
    :param username:
    :return: List of Users bookings
    """
    if username not in users:
        raise NotFound("User '{}' not found.".format(username))

    try:
        users_bookings = requests.get("http://127.0.0.1:5003/bookings/{}".format(username))
    except requests.exceptions.ConnectionError:
        raise ServiceUnavailable("The Bookings service is unavailable.")

    if users_bookings.status_code == 404:
        raise NotFound("No bookings were found for {}".format(username))

    users_bookings = users_bookings.json()

    # For each booking, get the rating and the movie title
    result = {}
    for date, movies in users_bookings.items():
        result[date] = []
        for movieid in movies:
            try:
                movies_resp = requests.get("http://127.0.0.1:5001/movies/{}".format(movieid))
            except requests.exceptions.ConnectionError:
                raise ServiceUnavailable("The Movie service is unavailable.")
            movies_resp = movies_resp.json()
            result[date].append({
                "title": movies_resp["title"],
                "rating": movies_resp["rating"],
                "uri": movies_resp["uri"]
            })

    return nice_json(result)

@app.route("/users/<username>/bookings/add", defaults={'page': '08022019'}, methods=['GET', 'POST'])
@app.route("/users/<username>/bookings/add/<page>", methods=['GET', 'POST'])
def user_bookings_add(username, page):

    if username not in users:
        raise NotFound("User '{}' not found.".format(username))

    if request.method == 'GET':
        result = {}
        try:
            showtimes = requests.get("http://127.0.0.1:5002/showtimes/{}".format(page))
        except requests.exceptions.ConnectionError:
            raise ServiceUnavailable("The Showtimes service is unavailable.")
		
        showtimes = showtimes.json()
       
        for movieid in showtimes:
            result[movieid] = []
            try:
                movies_resp = requests.get("http://127.0.0.1:5001/movies/{}".format(movieid))
            except requests.exceptions.ConnectionError:
                raise ServiceUnavailable("The Movie service is unavailable.")
            try:
                movies_resp = movies_resp.json()
            except ValueError:
                raise ServiceUnavailable("Sorry! No movies in this day.")
            result[movieid].append({
                "title": movies_resp["title"],
                "rating": movies_resp["rating"]
            })
			
        return nice_json(result)

    if request.method == 'POST':
        raw = request.get_json()
        result = requests.post("http://127.0.0.1:5003/bookings/{}/add".format(username), json={username:raw})
        result = result.json()
		
        user_resp = requests.get("http://127.0.0.1:5000/users/{}".format(username))
        user_resp = user_resp.json()
        content = {
            "id": user_resp["id"],
            "name": user_resp["name"],
            "last_active": 0
        }
        content = {username:content}
        with open("{}/database/users.json".format(root_dir())) as ff:
            data = json.load(ff)        
		
        data.update(content)
        with open("{}/database/users.json".format(root_dir()), "w+") as ff:
            json.dump(data,ff)
        users.update(content)	
        return nice_json(result)

    raise NotImplementedError()				


if __name__ == "__main__":
    app.run(port = 5000, debug = True)