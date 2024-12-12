from flask import *
import sqlite3
import uuid
from functools import wraps
import base64
import os

app=Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong, unique key
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


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

class Games_List:
    def __init__(self,game_name,game_genre,game_description,base_price):
        self.game_name=game_name
        self.game_genre=game_genre
        self.game_description=game_description
        self.base_price=base_price



          

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
        status TEXT CHECK(status IN ('Pending', 'Accepted', 'Rejected','Completed'))
    )
""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS SENT_FRIEND_REQUEST (
        username_from TEXT,
        username_to TEXT,
        request_status TEXT CHECK (request_status IN ('Pending', 'Accepted', 'Rejected')),
        FOREIGN KEY (username_from) REFERENCES USERS(username),
        FOREIGN KEY (username_to) REFERENCES USERS(username)
    )
""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS FRIENDS (
        username_me TEXT,
        username_friendswith TEXT,
        
        FOREIGN KEY (username_me) REFERENCES USERS(username),
        FOREIGN KEY (username_friendswith) REFERENCES USERS(username)
    )
""")
    #CREATIING GAME LIST TABLE
    c.execute("""
            CREATE TABLE IF NOT EXISTS GAME_LIST(
              game_name TEXT UNIQUE NOT NULL,
              game_genre TEXT NOT NULL,
              game_description TEXT NOT NULL,
              base_price INT NOT NULL
              CHECK(base_price between 0 AND 120),
              game_status TEXT CHECK(game_status in ('Active','Delisted')) NOT NULL,
              dev_username TEXT NOT NULL,
              rating_yes INT NOT NULL,
              rating_no INT NOT NULL, 
              copies_sold INT NOT NULL,
              revenue_generated INT NOT NULL,
              img_path_logo TEXT NOT NULL,
              img_path_ss1 TEXT NOT NULL,
              img_path_ss2 TEXT NOT NULL,
              game_file_path TEXT NOT NULL,
              sale_status TEXT CHECK(sale_status in(True,False)),
              actual_price INT NOT NULL CHECK(actual_price between 0 AND 120),
              sale_end_time DATETIME,
              FOREIGN KEY (dev_username) REFERENCES USERS(username)


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

      
        c.execute("SELECT username, user_type,store_region FROM USERS WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        c.execute("SELECT username, user_type FROM USERS WHERE username = ? AND password = ? AND account_status='active'", (username, password))
        user_active_check = c.fetchone()
        print("Fetched user:", user)

        if user:
            if user_active_check:
        
                session['username'] = user[0]
                session['user_type'] = user[1]
                session['store_region']=user[2]
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


@app.route('/dev_dashboard', methods=['GET','POST'])
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

        c.execute("SELECT game_name, status from GAME_PUBLISH_REQUEST WHERE username=?",(session['username'],))
        game_req_data = c.fetchall()
        c.execute("SELECT game_name,game_status, base_price,copies_sold,sale_status,actual_price,sale_end_time FROM GAME_LIST WHERE dev_username=?",(dev_username,))
        game_list_data=c.fetchall()
        print(game_list_data)
        c.execute("SELECT COUNT(*) FROM GAME_LIST WHERE dev_username=?",(dev_username,))
        no_of_total_games=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM GAME_LIST WHERE dev_username=? AND game_status='Active'",(dev_username,))
        no_of_games_active=c.fetchone()[0]
        c.execute("SELECT SUM(copies_sold) FROM GAME_LIST WHERE dev_username=?",(dev_username,))
        no_of_total__games_sold=c.fetchone()[0]
        delisted_games_count=no_of_total_games-no_of_games_active
        
        

        # c.execute("SELECT COUNT(*) FROM USERS WHERE user_type ='buyer' and account_status = 'terminated'")
        # terminated_users = c.fetchone()[0]
        # c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        # balance = c.fetchone()[0]
        # c.execute("SELECT username FROM USERS WHERE user_type ='buyer' and account_status = 'active'")
        # all_users = c.fetchall()
    return render_template('dev_dashboard.html',dev_username=dev_username, balance=balance,company_name=company_name,
                           publisher_name=publisher_name.upper(),dev_email=dev_email,game_req_data=game_req_data,game_list_data=game_list_data,
                           no_of_total__games_sold=no_of_total__games_sold, no_of_total_games= no_of_total_games,no_of_games_active=no_of_games_active,
                           delisted_games_count=delisted_games_count)

@app.route('/buyer_dashboard',methods=['GET','POST'])
@login_required('buyer')
def buyer_dashboard():
    connect_db()
    # Buyer-specific logic
    buyer_username=session['username']
    with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]
        

    return render_template('buyer_storefront.html', buyer_username=buyer_username,balance=balance)




@app.route('/ViewMyProfile',methods=['GET','POST'])
@login_required('buyer')
def buyer_profile():
    buyer_username=session['username']
    with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]
        c.execute("SELECT username,email,buyer_address,store_region,card_info, account_status FROM USERS where username=?",(session['username'],))
        buyer_details=c.fetchone()
        status=buyer_details[5].upper()
        card_info=str(buyer_details[4])
        c.execute("SELECT username_from FROM SENT_FRIEND_REQUEST where username_to=? and request_status='Pending'",(session['username'],))
        pending_requests=c.fetchall()
        c.execute("SELECT username_friendswith FROM FRIENDS where username_me=?",(session['username'],))
        my_friends=c.fetchall()

    return render_template('Buyer_profile.html',balance=balance,buyer_username=buyer_username,buyer_data=buyer_details,account_status=status,
                           card_info=card_info,pending_requests=pending_requests,my_friends=my_friends,store_region=session['store_region'])







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

@app.route('/DelistGame', methods=['POST'])
def Delist_game():
    data = request.json  
    game_name = data.get('game_name')

    if game_name:
        with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
            c = db.cursor()
            c.execute("UPDATE GAME_LIST SET game_status = 'Delisted' WHERE game_name = ?", (game_name,))
            db.commit()
        return jsonify({"message": f"{game_name} delisted successfully."})
    else:
        return jsonify({"error": "Invalid request"}), 400





@app.route('/SendFriendRequest', methods=['GET','POST'])
@login_required('buyer')
def Send_Friend_Request():
     if request.method == 'POST':
        db=sqlite3.connect("bashpos_--definitely--_secured_database.db")
        c=db.cursor()
        req_json = request.json
        friend_email=req_json.get('email')
        sender_username=session['username']
        c.execute("SELECT username FROM USERS where email=? and user_type='buyer'",(friend_email,))
        friend_username=c.fetchone()
        if  friend_username==None:
            return jsonify({"success": False, "message": "This email doesn't belong to a buyer or doesn't exist"})
        else:
            friend_username=friend_username[0]   
        if friend_username==session['username']:
             return jsonify({"success": False, "message": "You cannot send a friend request to yourself"})
        print(friend_username)
        #checking if a request is pending or accepted
        c.execute("SELECT request_status FROM SENT_FRIEND_REQUEST WHERE username_from=? and username_to=? and request_status!='Rejected'",(sender_username,friend_username))
        check_duplicate=c.fetchall()
        c.execute("SELECT request_status FROM SENT_FRIEND_REQUEST WHERE username_from=? and username_to=? and request_status!='Rejected'",(friend_username,sender_username))
        check_duplicate_2=c.fetchall()
        if len(check_duplicate)!=0:
            return jsonify({"success": False, "message": "Cannot send friend request as currently a request is "+check_duplicate[0][0]})
        elif len(check_duplicate_2)!=0:
            return jsonify({"success": False, "message": "Cannot send friend request as currently a request is "+check_duplicate_2[0][0]})
        else:
            c.execute("INSERT INTO SENT_FRIEND_REQUEST VALUES (?,?,?)",(sender_username,friend_username,'Pending'))
            db.commit()
            return jsonify({"success": True, "message": "Friend Request sent succesfully"})


@app.route('/updateFriendRequest', methods=['POST'])
@login_required('buyer')
def update_FriendRequest():
 
    req_json = request.json
    friends_username = req_json.get('username_from')
    status = req_json.get('request_status')

    if not friends_username or status not in ['Accepted', 'Rejected']:
        return jsonify({"response": "Invalid request data"}), 400
    db = sqlite3.connect('bashpos_--definitely--_secured_database.db')
    c = db.cursor()
    c.execute(
        "UPDATE SENT_FRIEND_REQUEST SET request_status=? WHERE username_from=? and username_to=?",
        (status, friends_username,session['username']),
    )
    if status=='Accepted':
        c.execute("INSERT INTO FRIENDS VALUES (?,?)",(session['username'],friends_username))
        db.commit()
        c.execute("INSERT INTO FRIENDS VALUES (?,?)",(friends_username,session['username']))
    db.commit()
    return jsonify({"message": "Request updated to "+status})        


@app.route('/ViewFriendProfile/<friend_username>')
def view_friend_profile(friend_username):
     with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]
        c.execute("SELECT email,account_status FROM USERS WHERE username=?",(friend_username,))
        friend_data=c.fetchone()
        # Pass the friend's username to the template
        return render_template('ViewFriendProfile.html', friendusername=friend_username,buyer_username=session['username'],balance=balance,friend_email=friend_data[0],friend_account_status=friend_data[1].upper())
     
@app.route('/UploadGameDataForm/<game_name>')
def uploadgamedta_formpage(game_name):
     with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:

        
        # Pass the friend's username to the template
        return render_template('upload_game_data.html',game_name=game_name,dev_username=session['username'])
     








@app.route('/ViewBuyerProfile/<buyer_username>')
def view_buyer_profile(buyer_username):
     with sqlite3.connect('bashpos_--definitely--_secured_database.db') as db:
        c = db.cursor()
        c.execute("SELECT balance FROM WALLET_BALANCE WHERE username = ?",(session['username'],))
        balance = c.fetchone()[0]
        c.execute("SELECT email,account_status FROM USERS WHERE username=?",(buyer_username,))
        buyer_data=c.fetchone()
        # Pass the friend's username to the template
        return render_template('ViewBuyerProfile.html', friendusername=buyer_username,username=session['username'],balance=balance,friend_email=buyer_data[0],friend_account_status=buyer_data[1].upper())


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
        
@app.route('/uploadgamedata', methods=['GET','POST'])
def uploadgamedata():
     if request.method == 'POST':
        db=sqlite3.connect("bashpos_--definitely--_secured_database.db")
        c=db.cursor()
        req_json = request.json
        game_name=req_json.get('game_name')
        game_genre=req_json.get('game_genre')
        dev_username=req_json.get('dev_username')
        game_description=req_json.get('game_description')
        base_price=req_json.get('base_price')
        logo=req_json.get('logo')
        screenshot1=req_json.get('screenshot1')
        screenshot2=req_json.get('screenshot2')
        game_file=req_json.get('game_file')
        
        print(game_description)
        logo_data = base64.b64decode(logo)

        # Generate a safe filename for the image
        filename = f"{game_name.replace(' ', '_').lower()}_logo.png"
        logo_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image to the upload folder
        with open(logo_file_path, 'wb') as f:
            f.write(logo_data)
        
        ss1_data = base64.b64decode(screenshot1)

        # Generate a safe filename for the image
        filename = f"{game_name.replace(' ', '_').lower()}_ss1.png"
        ss1_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image to the upload folder
        with open(ss1_file_path, 'wb') as f:
            f.write(ss1_data)

        ss2_data = base64.b64decode(screenshot2)

        # Generate a safe filename for the image
        filename = f"{game_name.replace(' ', '_').lower()}_ss2.png"
        ss2_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image to the upload folder
        with open(ss2_file_path, 'wb') as f:
            f.write(ss2_data) 
        
        game_file_data = base64.b64decode(game_file)

        # Generate a safe filename for the image
        filename = f"{game_name.replace(' ', '_').lower()}_file.zip"
        game_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image to the upload folder
        with open(game_file_path, 'wb') as f:
            f.write(game_file_data)     

 #########images send to  static/upload AND we will save the path data in DB
                 # def __init__(self,game_name,game_genre,game_description,base_price):
        game_data=Games_List(game_name,game_genre,game_description,base_price)
        c.execute("  INSERT INTO GAME_LIST VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (game_data.game_name,game_data.game_genre,
                game_data.game_description,game_data.base_price,'Active',dev_username,0,0,0,0,logo_file_path,ss1_file_path,ss2_file_path,game_file_path,False,game_data.base_price,None))
        
        c.execute("UPDATE GAME_PUBLISH_REQUEST SET status = 'Completed' WHERE username = ? and game_name=?", (dev_username, game_name))
        db.commit()
        return jsonify({"message": "Data for "+game_name+" uploaded successfully"})








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