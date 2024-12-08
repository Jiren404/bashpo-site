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
        self.account_status='active'

class Game_publish_request:
      def __init__(self,game_name,game_genre,estimated_release_year,basic_description):
            self.request_id=uuid.uuid4().hex
            self.username=''
            self.game_name=game_name
            self.game_genre=game_genre
            self.estimated_release_year=estimated_release_year
            self.basic_description=basic_description
            self.status='Pending'        

def connect_db():
    db=sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c=db.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS USERS(
        username TEXT PRIMARY KEY UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        buyer_address TEXT,
        store_region TEXT CHECK(store_region IN('NA','LA','EU','ASI','')),
        card_info INT,
        company_name TEXT,
        publisher_name TEXT CHECK(publisher_name IN('bandai_namco','playstation_publishing','xbox_game_studios','square_enix','self','')),
        user_type TEXT CHECK(user_type IN('buyer','developer','admin')) NOT NULL,
        account_status TEXT CHECK(account_status IN('active','terminated')) NOT NULL
    )
""")

    c.execute("""
        CREATE TABLE IF NOT EXISTS WALLET_BALANCE (
            username TEXT PRIMARY KEY,
            balance REAL DEFAULT 0,
            FOREIGN KEY (username) REFERENCES USERS(username)
        )
    """)

    c.execute("SELECT * FROM USERS WHERE username = 'LordGaben'")
    existing_user = c.fetchone()

    if existing_user is None:
        # Insert the user with the password for the first time
        c.execute("""
            INSERT INTO USERS (username, email, password, user_type, account_status)
            VALUES ('LordGaben', 'newell@steampowered.com', '123456', 'admin', 'active')
        """)
        db.commit()


    c.execute("""
    INSERT INTO WALLET_BALANCE (username, balance)
    SELECT ?, ?
    WHERE NOT EXISTS (
        SELECT 1 FROM WALLET_BALANCE WHERE username = ?
    )
""", ('LordGaben', 0, 'LordGaben'))
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS GAME_PUBLISH_REQUEST(
        request_id TEXT, 
        username TEXT,
        game_name TEXT, 
        game_genre TEXT, 
        estimated_release_year INT(4), 
        basic_description TEXT, 
        status TEXT CHECK(status IN ('Pending', 'Accepted', 'Rejected'))
    )
""")
    

    db.commit()
    c.connection.close()


@app.route('/')
def index():
    connect_db()

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
    
    if request.method == 'GET':
        return render_template('index.html')
    

    if request.is_json:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        print(f"Username: {username}, Password: {password}")

      
        c.execute("SELECT username, user_type FROM USERS WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        c.execute("SELECT username, user_type FROM USERS WHERE username = ? AND password = ? AND account_status='active'", (username, password))
        user_active_check = c.fetchone()
        print("Fetched user:", user)

        if user:
            if user_active_check:
        
                session['username'] = user[0]
                session['user_type'] = user[1]
            else:
                 return jsonify({"error": "Account Terminated due to fraudent activities"}), 401    

            return jsonify({
                "success": True,
                "redirect_url": url_for(f"{user[1]}_dashboard") 
            }), 200  
        else:
         
            return jsonify({"error": "Invalid credentials"}), 401  
   
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('login')) 


@app.route('/current_user')
def current_user():
    if 'user_type' in session:
        username = session['username']
        

        db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
        c = db.cursor()
        

        c.execute("SELECT email FROM USERS WHERE username = ?", (username,))
        user_data = c.fetchone()
        
        
        if user_data:
            return jsonify({"username": username, "user_type": session['user_type'], "email": user_data[0]})
        else:
            return jsonify({"error": "User data not found"})
        
    else:
        return jsonify({"error": "Not logged in"})

@app.route('/newacc', methods=['GET'])
def new_account_buyer():

    return render_template('newacc.html')  

@app.route('/forgotpass', methods=['GET'])
def forgot_pass():

    return render_template('forgotpass.html')



@app.route('/forgot_password', methods=['POST'])
def forgot_password():

    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

  
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400  

   
    db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c = db.cursor()
    c.execute("SELECT email FROM USERS WHERE email = ?", (email,))
    user = c.fetchone()


    if not user:
        return jsonify({"error": "Email not found."}), 404  

    c.execute("UPDATE USERS SET password = ? WHERE email = ?", (new_password, email))
    db.commit()
    db.close()


    return jsonify({"success": "Password reset successfully."}), 200 






@app.route('/devacc', methods=['GET'])
def new_account_developer():
 
    return render_template('devacc.html') 



@app.route('/create_buyer', methods=['POST'])
def create_buyer():
    db=sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c=db.cursor()
   
    if not request.is_json:
        return jsonify({"error": "Invalid request. Please send data as JSON."}), 400

   
    data = request.json
    username = data.get('user_name')
    email = data.get('email')
    password = data.get('password')
    buyer_address = data.get('buyer_address')
    store_region = data.get('store_region')
    card_info = data.get('card_info')
    print(username,email)
    
    if not (username and email and password and buyer_address and store_region and card_info):
        return jsonify({"error": "All fields are required."}), 400


    new_buyer = User(username, email, password, "buyer")
    new_buyer.buyer_address = buyer_address
    new_buyer.store_region = store_region
    new_buyer.card_info = card_info
    print(new_buyer.username)
  

    user_check=checkUser()  
    print(user_check)  
    if len(user_check)!=0:
        return jsonify({"error": "Username or email already exists."}), 400

    else: 
        c.execute("""
            INSERT INTO USERS (username, email, password, buyer_address, store_region, card_info, user_type,account_status)
            VALUES (?, ?, ?, ?, ?, ?, ?,?)
        """, (new_buyer.username, new_buyer.email, new_buyer.password, 
                new_buyer.buyer_address, new_buyer.store_region, new_buyer.card_info, 
                new_buyer.user_type,'active'))
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

    if not request.is_json:
        return jsonify({"error": "Invalid request. Please send data as JSON."}), 400

   
    data = request.json
    username = data.get('user_name')
    email = data.get('email')
    password = data.get('password')
    company_name = data.get('company_name')
    publisher_name = data.get('publisher_name')
   
    print(username,email)
   
    if not (username and email and password and company_name and publisher_name ):
        return jsonify({"error": "All fields are required."}), 400

    new_developer = User(username, email, password, "developer")
    new_developer.company_name = company_name
    new_developer.publisher_name = publisher_name
    
    print(new_developer.username)
  

    user_check=checkUser()  
    print(user_check)  
    if len(user_check)!=0:
        return jsonify({"error": "Username or email already exists."}), 400

 
    else: 
        c.execute("""
            INSERT INTO USERS (username, email, password, company_name, publisher_name, user_type,account_status)
            VALUES (?, ?, ?, ?, ?, ?,?)
        """, (new_developer.username, new_developer.email, new_developer.password, 
                new_developer.company_name, new_developer.publisher_name, 
                new_developer.user_type,'active'))
        c.execute("""
    INSERT INTO WALLET_BALANCE VALUES (?,?)
                  """,(new_developer.username,0))
        db.commit()
        db.close()

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
                return redirect(url_for('login'))  
            if session['user_type'] != role:
                return "Unauthorized Access", 403  
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper


@app.route('/dev_dashboard')
@login_required('developer')
def developer_dashboard():
    connect_db()
    with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT username,company_name,publisher_name,email FROM USERS WHERE user_type ='developer' and username=?",(session['username'],))
        dev_data = c.fetchone()
        dev_username=dev_data[0]
        company_name=dev_data[1]
        publisher_name=dev_data[2]
        dev_email=dev_data[3]
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]

        c.execute("SELECT game_name, status from GAME_PUBLISH_REQUEST WHERE username=? and status!='Pending'",(session['username'],))
        game_req_data = c.fetchall()

        # c.execute("SELECT COUNT(*) FROM USERS WHERE user_type ='buyer' and account_status = 'terminated'")
        # terminated_users = c.fetchone()[0]
        # c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        # balance = c.fetchone()[0]
        # c.execute("SELECT username FROM USERS WHERE user_type ='buyer' and account_status = 'active'")
        # all_users = c.fetchall()
    return render_template('dev_dashboard.html',dev_username=dev_username, balance=balance,company_name=company_name,
                           publisher_name=publisher_name.upper(),dev_email=dev_email,game_req_data=game_req_data)

@app.route('/buyer_dashboard')
@login_required('buyer')
def buyer_dashboard():
    # Buyer-specific logic
    return render_template('buyer_storefront.html')

@app.route('/admin_dashboard')
@login_required('admin')
def admin_dashboard():
    with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT COUNT(*) FROM USERS WHERE user_type ='buyer' and account_status = 'active'")
        active_users = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM USERS WHERE user_type = 'developer'")
        developers = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM USERS WHERE user_type ='buyer' and account_status = 'terminated'")
        terminated_users = c.fetchone()[0]
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]
        c.execute("SELECT username FROM USERS WHERE user_type ='buyer' and account_status = 'active'")
        all_users = c.fetchall()
        c.execute("SELECT username,company_name FROM USERS WHERE user_type ='developer' and account_status = 'active'")
        all_devs = c.fetchall()       
        c.execute("""
        SELECT u.username, w.balance
        FROM USERS u
        INNER JOIN WALLET_BALANCE w ON u.username = w.username
        WHERE u.user_type = 'developer';
    """)
        

        developer_earnings=c.fetchall()

        all_requests=getRequests_admin()


    return render_template('admin_dashboard.html', username=session['username'], active_users=active_users, developers=developers, terminated_users=terminated_users, 
                           balance=balance,all_users=all_users,developer_earnings=developer_earnings,all_devs=all_devs,all_requests=all_requests)

@app.route('/get_active_buyers', methods=['GET'])
def get_active_buyers():
    with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT username FROM USERS WHERE user_type = 'buyer' AND account_status = 'active'")
        buyers = c.fetchall()  
    return jsonify(buyers)  

@app.route('/terminate_buyer', methods=['POST'])
def terminate_buyer():
    data = request.json  
    username = data.get('username')

    if username:
        with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
            c = db.cursor()
            c.execute("UPDATE USERS SET account_status = 'terminated' WHERE username = ?", (username,))
            db.commit()
        return jsonify({"message": f"User {username} terminated successfully."})
    else:
        return jsonify({"error": "Invalid request"}), 400







@app.route('/SendPublishingRequest', methods=['GET','POST'])

def Send_Publishing_Request():
    if request.method == 'POST':
        db=sqlite3.connect("bashpos_--definitely--_secured_database.db")
        c=db.cursor()
        req_json = request.json
        Pub_request=Game_publish_request(req_json["game_name"],req_json["game_genre"],req_json["estimated_release_year"],req_json["basic_description"])
        print(Pub_request)
        game_avail_check=getPub_Req_Avail(req_json["game_name"])
        if len(game_avail_check)!=0:
            return jsonify({"success": False, "message": "Cannot send request as request for a game with the same name has already been accepted or waiting for approval"})
        else:
            c.execute("INSERT INTO GAME_PUBLISH_REQUEST VALUES(?,?,?,?,?,?,?)",
                    (Pub_request.request_id,session['username'],Pub_request.game_name,Pub_request.game_genre,
                        Pub_request.estimated_release_year,Pub_request.basic_description
                        , Pub_request.status))
            db.commit()
            db.close()
        
            return  jsonify({"success": True,"message": "Publishing request for "+req_json['game_name']+ " sent successfully"})

@app.route('/getPubReq', methods=['GET'])
def getPub_Req_Avail(game_name):
    game_name=game_name
    c = sqlite3.connect("bashpos_--definitely--_secured_database.db").cursor()
    c.execute("SELECT * FROM GAME_PUBLISH_REQUEST where game_name=? and status!='Rejected'",(game_name,))
    data=c.fetchall()
    return data


@app.route('/getRequests', methods=['GET'])
def getRequests_admin():
    c = sqlite3.connect("bashpos_--definitely--_secured_database.db").cursor()
    c.execute("SELECT * FROM GAME_PUBLISH_REQUEST where status='Pending'")
    data=c.fetchall()
    return data


@app.route('/updateRequest', methods=['POST'])
@login_required('admin')
def update_request():
 
    req_json = request.json
    request_id = req_json.get('request_id')
    status = req_json.get('status')

    if not request_id or status not in ['Accepted', 'Rejected']:
        return jsonify({"response": "Invalid request data"}), 400
    db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c = db.cursor()
    c.execute(
        "UPDATE GAME_PUBLISH_REQUEST SET status=? WHERE request_id=?",
        (status, request_id),
    )
    if status=='Accepted':
        c.execute("UPDATE WALLET_BALANCE SET balance=balance+1000 where username='LordGaben'")
    db.commit()
    return jsonify({"message": "Request updated to "+status})


    
    






    
@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        username = session['username']
        db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
        c = db.cursor()

        
        c.execute("SELECT password FROM USERS WHERE username = ?", (username,))
        stored_password = c.fetchone()

        if stored_password and stored_password[0] == current_password:
            # Update the password
            print('newpass: ',new_password,username)
            c.execute("UPDATE USERS SET password = ? WHERE username = ?", (new_password, username))
            db.commit()
            db.close()

            return jsonify({"success": True, "message": "Password updated successfully!"})
        else:
            return jsonify({"success": False, "error": "Incorrect current password!"})

    return redirect(url_for('logout'))

if __name__=="__main__":
    app.run(debug=True, port=1097)