import sqlite3
import time
import hashlib
import uuid
from flask import Flask, request, jsonify, abort, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["5 per minute"]
)

# Connect to the SQLite database
conn = sqlite3.connect('oauth.db')
c = conn.cursor()

# Create a table to store user details
c.execute('''CREATE TABLE IF NOT EXISTS user_details
             (f_name TEXT, l_name TEXT, email_id TEXT PRIMARY KEY, phone_number TEXT, address TEXT, created_date INTEGER)''')
conn.commit()

# Create a table to store access tokens
c.execute('''CREATE TABLE IF NOT EXISTS access_tokens
             (id TEXT PRIMARY KEY, user_id TEXT, created_at INTEGER, expires_at INTEGER)''')
conn.commit()
conn.close()

# Set the token expiration time to 3 minutes
TOKEN_EXPIRATION_TIME = 180

    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/oauth/token', methods=['POST'])
def generate_token():
    conn = sqlite3.connect('oauth.db')
    c = conn.cursor()

    # Get the user ID from the request data
    user_id = request.form.get('user_id')
    
    # Generate a unique ID for the token
    token_id = str(uuid.uuid4())
    
    # Generate a timestamp for the token creation and expiration
    current_time = int(time.time())
    expires_at = current_time + TOKEN_EXPIRATION_TIME
    
    # Hash the token ID to store it securely
    hashed_token_id = hashlib.sha256(token_id.encode()).hexdigest()
    
    # Insert the access token into the database
    c.execute("INSERT INTO access_tokens VALUES (?, ?, ?, ?)", (hashed_token_id, user_id, current_time, expires_at))
    conn.commit()
    conn.close()
    # Return the access token to the user
    return jsonify({'access_token': token_id}), 200



@app.route('/user-details', methods=['POST'])
@limiter.limit("5 per minute")
def insert_user_details():
    conn = sqlite3.connect('oauth.db')
    c = conn.cursor()

    # Get the access token from the request headers
    access_token = request.headers.get('Authorization')
    
    # Hash the access token to compare it with the stored tokens in the database
    hashed_access_token = hashlib.sha256(access_token.encode()).hexdigest()
    
    # Check if the access token is valid and has not expired
    current_time = int(time.time())
    c.execute("SELECT * FROM access_tokens WHERE id = ? AND expires_at > ?", (hashed_access_token, current_time))
    token_data = c.fetchone()
    
    if not token_data:
        return jsonify({'message': 'Invalid or expired access token'}), 401
    
    # Get the user details from the request data
    f_name = request.form.get('f_name')
    l_name = request.form.get('l_name')
    email_id = request.form.get('email_id')
    phone_number = request.form.get('phone_number')
    address = request.form.get('address')
    
    # Generate a timestamp for the user creation date
    created_date = int(time.time())
    
    # Insert the user details into the database
    c.execute("INSERT INTO user_details VALUES (?, ?, ?, ?, ?, ?)", (f_name, l_name, email_id, phone_number, address, created_date))
    conn.commit()
    conn.close()

    # Return a success message to the user
    return jsonify({'message': 'User details added successfully'}), 200



# Function to get the list of users with pagination and sorting
def get_users(page, limit, sort):
    conn = sqlite3.connect('oauth.db')
    c = conn.cursor()
    
    # Get the total number of users
    c.execute('SELECT COUNT(*) FROM user_details')
    total_users = c.fetchone()[0]
    
    # Calculate the offset for pagination
    offset = (page - 1) * limit
    
    # Get the list of users with sorting and pagination
    c.execute(f'SELECT * FROM user_details ORDER BY created_date {sort} LIMIT ? OFFSET ?', (limit, offset))
    users = c.fetchall()
    
    # Generate the next and previous page URLs
    next_page = f'/users?page={page+1}&limit={limit}&sort={sort}' if offset+limit < total_users else None
    prev_page = f'/users?page={page-1}&limit={limit}&sort={sort}' if offset > 0 else None
    conn.commit()
    conn.close()
    
    return users, next_page, prev_page

# API endpoint to list users with pagination and sorting
@app.route('/users', methods=['GET'])
@limiter.limit("5 per minute")
def list_users():
    conn = sqlite3.connect('oauth.db')
    c = conn.cursor()
    # Check for access token in request headers
    access_token = request.headers.get('Authorization')  

    if not access_token:
        abort(401, 'Access token not found')

    # Hash the access token to compare it with the stored tokens in the database
    hashed_access_token = hashlib.sha256(access_token.encode()).hexdigest()
    
    # Check if the access token is valid and has not expired
    current_time = int(time.time())
    c.execute("SELECT * FROM access_tokens WHERE id = ? AND expires_at > ?", (hashed_access_token, current_time))
    token_data = c.fetchone()

    if not token_data:
        return jsonify({'message': 'Invalid or expired access token'}), 401
    
    
    conn.commit()
    conn.close()
    # Get pagination and sorting parameters from query string
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=5, type=int)
    sort = request.args.get('sort', default='DESC', type=str)
    
    # Check for valid sort parameter
    if sort not in ['ASC', 'DESC']:
        abort(400, 'Invalid sort parameter')
    
    # Get the list of users with pagination and sorting
    users, next_page, prev_page = get_users(page, limit, sort)
    
    # Generate response
    response = {
        'users': users,
        'pagination': {
            'next_url': next_page,
            'prev_url': prev_page
        }
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
