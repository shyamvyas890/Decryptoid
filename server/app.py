from flask import Flask, request, jsonify, make_response
from flaskext.mysql import MySQL
import bcrypt
import jwt
import datetime
from datetime import timezone
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="http://localhost:3000", supports_credentials=True)

app.config['MYSQL_DATABASE_HOST'] = 'localhost' 
app.config['MYSQL_DATABASE_USER'] = 'root' 
app.config['MYSQL_DATABASE_PASSWORD'] = 'password'  
app.config['MYSQL_DATABASE_DB'] = 'Decryptoid'
secretKey = "secretKey" # will change later

db = MySQL(app)

@app.route('/')
def hello_world():
    return 'Hello, World!'

def hashedPassword(plaintextPassword):
    salt = bcrypt.gensalt(rounds=13)
    return bcrypt.hashpw(plaintextPassword.encode('utf-8'), salt)

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return "You need to include both a username and a password", 400
    theHashedPassword = hashedPassword(password)
    conn= None
    cursor = None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username));
        rows= cursor.fetchall()
        if(len(rows)==1):
            cursor.close()
            conn.close()
            return "This username is already taken. Please choose a different username.", 400
        cursor.execute("INSERT INTO Users (Username, PasswordHash) VALUES (%s,%s)",(username, theHashedPassword))
        conn.commit()
        cursor.close()
        conn.close()
        return "User Registered Successfully", 201
    except Exception as e:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(e)

        return "Internal Server Error", 500

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return "You need to include both a username and a password", 400
    conn = None
    cursor= None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username))
        rows= cursor.fetchall()
        cursor.close()
        conn.close()
        if(len(rows)==0):
            return "This username does not exist.", 400
        if(not bcrypt.checkpw(password.encode('utf-8'), rows[0][2].encode('utf-8'))):
            return "Your password is incorrect.", 401
        else:
            payload= {"UserId": rows[0][0], 
                    "Username": rows[0][1],
                    'exp': datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=24)}
            token= jwt.encode(payload, secretKey,algorithm='HS256')
            response = make_response("Login Successful")
            response.status_code = 200
            response.set_cookie('theJSONWebToken', token, max_age=86400, httponly=True)
            return response
    except Exception as e:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(e)
        return "Internal Server Error", 500
    
        
@app.route('/verify-token', methods=['GET'])
def verify_token():
    theToken=request.cookies.get("theJSONWebToken")
    if(theToken is None):
        response = make_response("No token provided")
        response.status_code=401
        return response
    conn=None
    cursor=None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken))
        rows= cursor.fetchall()
        if(len(rows)!=0):
            response = make_response("Token is blacklisted")
            response.status_code=401
            response.set_cookie('theJSONWebToken', '', expires=0)
            cursor.close()
            conn.close()
            return response
        try:
            decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
            cursor.close()
            conn.close()
            return make_response(jsonify(decodedToken))

        except Exception as decodingTokenException:
            print(decodingTokenException)
            cursor.close()
            conn.close()
            response = make_response("Token is invalid")
            response.status_code=401
            response.set_cookie('theJSONWebToken', '', expires=0)
            return response
    except Exception as ServerException:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(ServerException)
        return "Internal Server Error", 500
@app.route('/logout', methods=['POST'])
def logout():
    theToken=request.cookies.get("theJSONWebToken")
    if(theToken is None):
        response = make_response("No token provided")
        response.status_code=401
        return response
    conn=None
    cursor=None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken))
        rows= cursor.fetchall()
        if(len(rows)!=0):
            response = make_response("Succesfully Logged Out")
            cursor.close()
            conn.close()
            return response
        try:
            jwt.decode(theToken, secretKey, algorithms="HS256")
            cursor.execute("INSERT INTO BlacklistedTokens (Token) VALUES (%s)",(theToken))
            conn.commit()
            cursor.close()
            conn.close()
            response= make_response("Successfully Logged Out")
            response.set_cookie('theJSONWebToken', '', expires=0)
            return response
        except Exception as decodingTokenException:
            print(decodingTokenException)
            cursor.close()
            conn.close()
            return "Token is invalid", 401
    except Exception as ServerException:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(ServerException)
        return "Internal Server Error", 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)