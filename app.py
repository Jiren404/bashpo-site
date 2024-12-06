from flask import *
import sqlite3
import uuid
from functools import wraps

app=Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong, unique key


class User:
    def __init__(self,username,email,password,user_type):
        self.username=username
        self.email=email
        self.password=password
        self.buyer_address=''
        self.store_region=''
        self.card_info=''
        self.company_name=''
        self.publisher_name=''
        self.user_type=user_type

def connect_db():
    c=sqlite3.connect('bashpos_--definitely--_secured_database.db').cursor()
    c.execute("""
                CREATE TABLE IF NOT EXISTS USERS(
              username TEXT UNIQUE NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL,
              buyer_address TEXT,
              store_region TEXT CHECK(store_region IN('NA','LA','EU','ASI','')),
              card_info INT,
              company_name TEXT,
              publisher_name TEXT CHECK(publisher_name IN('bandai_namco','playstation_publishing','xbox_game_studios','square_enix','self','')),
              user_type TEXT CHECK(user_type IN('buyer','developer','admin'))
              )
              """)      
    c.execute("""
    CREATE TABLE IF NOT EXISTS WALLET_BALANCE (
        username TEXT PRIMARY KEY,
        balance REAL DEFAULT 0,
        FOREIGN KEY (username) REFERENCES USERS(username)
    )
""")

    c.connection.close()


@app.route('/')
def index():
    connect_db()
    # Check session for user_type and redirect accordingly
    if 'user_type' in session:
        if session['user_type'] == 'buyer':
            return redirect(url_for('buyer_dashboard'))
        elif session['user_type'] == 'developer':
            return redirect(url_for('developer_dashboard'))
        elif session['user_type'] == 'admin':
            return redirect(url_for('admin_dashboard'))
    # If no session, redirect to login
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c = db.cursor()
    
    # If the request is a GET request, render the login page
    if request.method == 'GET':
        return render_template('index.html')
    
    # If the request is a POST request (with JSON data)
    if request.is_json:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        print(f"Username: {username}, Password: {password}")

        # Authenticate user
        c.execute("SELECT username, user_type FROM USERS WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        print("Fetched user:", user)

        if user:
            # Set session data
            session['username'] = user[0]
            session['user_type'] = user[1]

            # Respond with success and user type
            return jsonify({
                "success": True,
                "redirect_url": url_for(f"{user[1]}_dashboard")  # Redirect to appropriate dashboard based on user type
            }), 200  # 200 OK response
        else:
            # Return an error if the credentials are invalid
            return jsonify({"error": "Invalid credentials"}), 401  # 401 Unauthorized

    # If the request is not JSON, just render the login page
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('login'))  # Redirect to login page

# Route to fetch the current user's account info from session
@app.route('/current_user')
def current_user():
    if 'user_type' in session:
        username = session['username']
        
        # Connect to the database
        db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
        c = db.cursor()
        
        # Query to get the email of the logged-in user
        c.execute("SELECT email FROM USERS WHERE username = ?", (username,))
        user_data = c.fetchone()
        
        # If user is found, return username, email, and user_type
        if user_data:
            return jsonify({"username": username, "user_type": session['user_type'], "email": user_data[0]})
        else:
            return jsonify({"error": "User data not found"})
        
    else:
        return jsonify({"error": "Not logged in"})

@app.route('/newacc', methods=['GET'])
def new_account_buyer():
    # Render the buyer account creation page
    return render_template('newacc.html')  # Replace with the actual buyer signup HTML file

@app.route('/forgotpass', methods=['GET'])
def forgot_pass():
    # Render the buyer account creation page
    return render_template('forgotpass.html')



@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    # Retrieve the form data (email, new password, and confirmed password)
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    # Check if new password and confirm password match
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400  # 400 Bad Request

    # Check if the email exists in the database
    db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c = db.cursor()
    c.execute("SELECT email FROM USERS WHERE email = ?", (email,))
    user = c.fetchone()

    # If the email doesn't exist, return an error
    if not user:
        return jsonify({"error": "Email not found."}), 404  # 404 Not Found

    # If email exists, update the password
    c.execute("UPDATE USERS SET password = ? WHERE email = ?", (new_password, email))
    db.commit()
    db.close()

    # Return a success response
    return jsonify({"success": "Password reset successfully."}), 200  # 200 OK






@app.route('/devacc', methods=['GET'])
def new_account_developer():
    # Render the developer account creation page
    return render_template('devacc.html')  # Replace with the actual developer signup HTML file



@app.route('/create_buyer', methods=['POST'])
def create_buyer():
    db=sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c=db.cursor()
    # Retrieve form data from the request
    if not request.is_json:
        return jsonify({"error": "Invalid request. Please send data as JSON."}), 400

    # Retrieve JSON data from the request
    data = request.json
    username = data.get('user_name')
    email = data.get('email')
    password = data.get('password')
    buyer_address = data.get('buyer_address')
    store_region = data.get('store_region')
    card_info = data.get('card_info')
    print(username,email)
    # Validate required fields
    if not (username and email and password and buyer_address and store_region and card_info):
        return jsonify({"error": "All fields are required."}), 400

    # Create a new User instance
    new_buyer = User(username, email, password, "buyer")
    new_buyer.buyer_address = buyer_address
    new_buyer.store_region = store_region
    new_buyer.card_info = card_info
    print(new_buyer.username)
  

        # If user already exists, return an error
    user_check=checkUser()  
    print(user_check)  
    if len(user_check)!=0:
        return jsonify({"error": "Username or email already exists."}), 400

    # Insert new buyer into the database
    else: 
        c.execute("""
            INSERT INTO USERS (username, email, password, buyer_address, store_region, card_info, user_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (new_buyer.username, new_buyer.email, new_buyer.password, 
                new_buyer.buyer_address, new_buyer.store_region, new_buyer.card_info, 
                new_buyer.user_type))
        c.execute("""
    INSERT INTO WALLET_BALANCE VALUES (?,?)
                  """,(new_buyer.username,0))
        db.commit()
        db.close()

    # If successful, return success response
        return jsonify({"success": "Buyer account created successfully.", "redirect_url": url_for('index')}), 200



@app.route('/create_developer', methods=['POST'])
def create_developer():
    db=sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c=db.cursor()
    # Retrieve form data from the request
    if not request.is_json:
        return jsonify({"error": "Invalid request. Please send data as JSON."}), 400

    # Retrieve JSON data from the request
    data = request.json
    username = data.get('user_name')
    email = data.get('email')
    password = data.get('password')
    company_name = data.get('company_name')
    publisher_name = data.get('publisher_name')
   
    print(username,email)
    # Validate required fields
    if not (username and email and password and company_name and publisher_name ):
        return jsonify({"error": "All fields are required."}), 400

    # Create a new User instance
    new_developer = User(username, email, password, "developer")
    new_developer.company_name = company_name
    new_developer.publisher_name = publisher_name
    
    print(new_developer.username)
  

        # If user already exists, return an error
    user_check=checkUser()  
    print(user_check)  
    if len(user_check)!=0:
        return jsonify({"error": "Username or email already exists."}), 400

    # Insert new buyer into the database
    else: 
        c.execute("""
            INSERT INTO USERS (username, email, password, company_name, publisher_name, user_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (new_developer.username, new_developer.email, new_developer.password, 
                new_developer.company_name, new_developer.publisher_name, 
                new_developer.user_type))
        c.execute("""
    INSERT INTO WALLET_BALANCE VALUES (?,?)
                  """,(new_developer.username,0))
        db.commit()
        db.close()

    # If successful, return success response
        return jsonify({"success": "Developer account created successfully.", "redirect_url": url_for('index')}), 200






@app.route('/checkUser', methods=['GET'])
def checkUser():
    data = request.json
    username = data.get('user_name')
    email = data.get('email')
    c = sqlite3.connect("bashpos_--definitely--_secured_database.db").cursor()
    c.execute("SELECT * FROM USERS WHERE username = ? OR email = ?", (username, email))
    data=c.fetchall()
    return data




def login_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'user_type' not in session:
                return redirect(url_for('login'))  # Redirect to login if not logged in
            if session['user_type'] != role:
                return "Unauthorized Access", 403  # Return error if role mismatch
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


@app.route('/dev_dashboard')
@login_required('developer')
def developer_dashboard():
    # Developer-specific logic
    return render_template('dev_dashboard.html')

@app.route('/buyer_dashboard')
@login_required('buyer')
def buyer_dashboard():
    # Buyer-specific logic
    return render_template('buyer_storefront.html')

@app.route('/admin_dashboard')
@login_required('admin')
def admin_dashboard():
    # Buyer-specific logic
    return render_template('admin_dashboard.html')

if __name__=="__main__":
    app.run(debug=True, port=1097)