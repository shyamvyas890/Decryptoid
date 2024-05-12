from flask import Flask, request, jsonify, make_response
from flaskext.mysql import MySQL
import bcrypt, jwt, datetime, math, re
from datetime import timezone
from flask_cors import CORS
app = Flask(__name__)
CORS(app, origins="http://localhost:3000", supports_credentials=True)

app.config['MYSQL_DATABASE_HOST'] = 'localhost' 
app.config['MYSQL_DATABASE_USER'] = 'root' 
app.config['MYSQL_DATABASE_PASSWORD'] = 'password' # root for windows   
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
    email = request.json.get('email')
    if not username or not password or not email:
        return "You need to include a username, email and a password", 400
    usernamePattern = r"^[a-zA-Z0-9_-]+$"
    if not re.fullmatch(usernamePattern, username):
        return "That is not a valid username.", 400
    emailPattern = r'^[a-zA-Z0-9._]+@[a-zA-Z0-9.]+\.[a-zA-Z]{2,}$'
    if not re.fullmatch(emailPattern, email):
        return "That is not a valid email.", 400
    theHashedPassword = hashedPassword(password)
    conn= None
    cursor = None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
        rows= cursor.fetchall()
        if(len(rows)==1):
            cursor.close()
            conn.close()
            return "This username is already taken. Please choose a different username.", 400
        cursor.execute("SELECT * FROM Users WHERE Email = %s", (email,))
        rows= cursor.fetchall()
        if(len(rows)==1):
            cursor.close()
            conn.close()
            return "This email is already taken. Please choose a different email.", 400
        print("made it here")
        cursor.execute("INSERT INTO Users (Username, Email, PasswordHash) VALUES (%s,%s,%s)",(username, email, theHashedPassword))
        conn.commit()
        payload= {"UserId": cursor.lastrowid, 
                  "Username": username,
                  'exp': datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=24)}
        token= jwt.encode(payload, secretKey,algorithm='HS256')
        response = make_response("User Registered Successfully")
        response.status_code=201
        response.set_cookie('theJSONWebToken', token, max_age=86400, httponly=True)
        cursor.close()
        conn.close()
        return response
    except Exception as e:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(e)
        return "Something went wrong", 500

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
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
        rows= cursor.fetchall()
        cursor.close()
        conn.close()
        if(len(rows)==0):
            return "This username does not exist.", 400
        if(not bcrypt.checkpw(password.encode('utf-8'), rows[0][3].encode('utf-8'))):
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
        response = make_response("Unauthorized")
        response.status_code=401
        return response
    conn=None
    cursor=None
    try:
        conn = db.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
        rows= cursor.fetchall()
        if(len(rows)!=0):
            response = make_response("Unauthorized")
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
            response = make_response("Unauthorized")
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
        cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
        rows= cursor.fetchall()
        if(len(rows)!=0):
            response = make_response("Succesfully Logged Out")
            cursor.close()
            conn.close()
            return response
        try:
            jwt.decode(theToken, secretKey, algorithms="HS256")
            cursor.execute("INSERT INTO BlacklistedTokens (Token) VALUES (%s)",(theToken,))
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
            return "Something is wrong with your request.", 401
    except Exception as ServerException:
        if(cursor):
            cursor.close()
        if(conn):
            conn.close()
        print(ServerException)
        return "Internal Server Error", 500
    
@app.route('/substitution', methods=['POST'])
def substitionEncrypt():
    file_contents=None
    if('encrypt' not in request.form):
        return "Must include encryption information", 400
    encrypt = True if request.form['encrypt']=="true" else False
    if('file' in request.files):
        uploaded_file = request.files['file']
        if(not uploaded_file.filename.lower().endswith('.txt')):
            return "Only txt files are accepted, sorry", 400
        file_contents = uploaded_file.read().decode('utf-8')
    elif ('file' in request.form):
        file_contents= request.form['file']
    else:
        return 'You have to include some content you want to encrypt', 400
    if 'cipher' not in request.form:
        return "No cipher provided", 400
    cipherContents = request.form['cipher'].split("-->")
    if(len(cipherContents[0]) != len(cipherContents[1])):
        return "Cipher is corrupted", 400
    cipherContent1 = [char for char in cipherContents[0]]
    cipherContent2 = [char for char in cipherContents[1]]
    theEncryptedContent =""
    try:
        for char in file_contents:
            if char == " ":
                theEncryptedContent += " "
                continue
            if (encrypt):
                index = cipherContent1.index(char)
                theEncryptedContent += cipherContent2[index]
            else:
                index = cipherContent2.index(char)
                theEncryptedContent += cipherContent1[index]
    except Exception as e:
        print(e)
        response = make_response("Your file can only contain lowercase english letters and spaces.")
        response.status_code = 400
        return response
    try:
        UserId = None
        conn = db.connect()
        cursor = conn.cursor()
        try:
            theToken=request.cookies.get("theJSONWebToken")
            cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
            rows= cursor.fetchall()
            if(len(rows)==0):
                decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                UserId = decodedToken.get('UserId')
            else:
                return "Unauthorized", 401 
        except Exception as decodingTokenException:
            print(decodingTokenException)
            return "Unauthorized", 401
        cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "substitution", UserId))
        conn.commit()
        cursor.close()
        conn.close()
        return theEncryptedContent,200
    except Exception as e:
        print(e)
        return "Internal Server Error", 500
    
def swap(the2DArray, rowOrColumn, index1, index2):
    if(rowOrColumn == "row"):
        temp = [char for char in the2DArray[index1]]
        for i in range(len(the2DArray[index2])):
            the2DArray[index1][i] = the2DArray[index2][i]
        for i in range(len(temp)):
            the2DArray[index2][i] = temp[i]
    elif (rowOrColumn == "column"):
        temp = []
        for i in range(len(the2DArray)):
            temp.append(the2DArray[i][index1])
        for i in range(len(the2DArray)):
            the2DArray[i][index1] = the2DArray[i][index2]
        for i in range(len(the2DArray)):
            the2DArray[i][index2] = temp[i]

@app.route('/doubleTransposition', methods=['POST'])
def doubleTranspositionEncrypt():
    file_contents=None
    numberOfCharactersInOriginalMessageIfDecrypt=None
    if('encrypt' not in request.form):
        return "Must include encryption information", 400
    encrypt = True if request.form['encrypt']=="true" else False
    if(not encrypt):
        if('numberOfCharactersInOriginalMessage' not in request.form):
            return "You must return the number of characters originally in the message if you want to decrypt with this cipher", 400
        try:
            numberOfCharactersInOriginalMessageIfDecrypt = int(request.form['numberOfCharactersInOriginalMessage'])
        except ValueError as valueError:
            print(valueError)
            return "The number of characters you entered is not a valid integer", 400
    if('file' in request.files):
        uploaded_file = request.files['file']
        if(not uploaded_file.filename.lower().endswith('.txt')):
            return "Only txt files are accepted, sorry", 400
        file_contents = uploaded_file.read().decode('utf-8')
    elif ('file' in request.form):
        file_contents= request.form['file']
    else:
        return 'You have to include some content you want to encrypt', 400
    if 'cipher' not in request.form:
        return "No cipher provided", 400
    cipherContents = request.form['cipher'] # alternateConsecutive
    theEncryptedContent =""
    columns = math.ceil(math.sqrt(len(file_contents)))
    rows= columns
    while (rows*columns>=len(file_contents)):
        if((rows-1)*columns >= len(file_contents)):
            rows-=1
        else:
            break
    transpositionMatrix = [["e"]*columns for _ in range(rows)]
    characterOneAtATime = [char for char in file_contents]
    characterOneAtATimeIndexCounter = 0
    for i in range(rows):
        for j in range(columns):
            if (characterOneAtATimeIndexCounter >= len(characterOneAtATime)):
                continue
            else:
                transpositionMatrix[i][j] = characterOneAtATime[characterOneAtATimeIndexCounter]
                characterOneAtATimeIndexCounter+=1
    
    if (encrypt):
        if(cipherContents == "alternateConsecutive"):
            lastColumn = columns if columns%2==0 else columns-1
            lastRow = rows if rows%2==0 else rows-1
            for i in range(0,lastColumn, 2):
                swap(transpositionMatrix, "column", i, i+1)
            for i in range(0, lastRow, 2):
                swap(transpositionMatrix, "row", i, i+1)
        for i in range(len(transpositionMatrix)):
            for j in range(len(transpositionMatrix[i])):
                theEncryptedContent += transpositionMatrix[i][j]
        try:
            UserId = None
            conn = db.connect()
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId')
                else:
                    return "Unauthorized", 401  
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",
                           (file_contents, "double transposition", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"theEncryptedContent":theEncryptedContent, "length": len(file_contents)}), 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
    else:
        if(cipherContents == "alternateConsecutive"):
            lastColumn = columns if columns%2==0 else columns-1
            lastRow = rows if rows%2==0 else rows-1
            for i in range(0, lastRow, 2):
                swap(transpositionMatrix, "row", i, i+1)
            for i in range(0,lastColumn, 2):
                swap(transpositionMatrix, "column", i, i+1)
        decryptionCounter = 0
        for i in range(len(transpositionMatrix)):
            for j in range(len(transpositionMatrix[i])):
                if(decryptionCounter<numberOfCharactersInOriginalMessageIfDecrypt):
                    theEncryptedContent += transpositionMatrix[i][j]
                    decryptionCounter+=1
        try:
            UserId = None
            conn = db.connect()
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId')
                else:
                    return "Unauthorized", 401  
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "double transposition", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return theEncryptedContent, 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
        
@app.route('/RC4', methods=['POST'])
def rc4EncryptDecrypt(): # todo: rename to handler 
    file_contents=None
    rc4key=None
    if('encrypt' not in request.form):
        return "Must include encryption information", 400
    encrypt = True if request.form['encrypt']=="true" else False
    if(not encrypt):
        if('rc4key' not in request.form):
            return "Must include key for decryption", 400
        if(request.form['rc4key']==""):
            return "Must include key for decryption", 400
        rc4key = str(request.form['rc4key'])
    if(encrypt):
        if('rc4key' not in request.form):
            return "Must include key for encryption", 400
        if(request.form['rc4key']==""):
            return "Must include key for encryption", 400
        rc4key = str(request.form['rc4key'])
    if('file' in request.files):
        uploaded_file = request.files['file']
        if(not uploaded_file.filename.lower().endswith('.txt')):
            return "Only txt files are accepted, sorry", 400
        file_contents = uploaded_file.read().decode('utf-8')
    elif ('file' in request.form):
        file_contents= request.form['file']
    else:   
        return 'You have to include some content you want to encrypt', 400
    cipherContents = "RC4" 
    theEncryptedContent = ""
    if (encrypt): 
        if(cipherContents == "RC4"):  
            plainTextToByte = file_contents.encode() 
            ciphertext = rc4_encrypt(plainTextToByte, rc4key)
            hexaCiphertext = ''.join(f'{b:02x}' for b in ciphertext) #format ints into hexStrings
            theEncryptedContent = hexaCiphertext
        try:
            UserId = None
            conn = db.connect() 
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId')
                else:
                    return "Unauthorized", 401
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "RC4", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"theEncryptedContent":theEncryptedContent, "length": len(file_contents)}), 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
    else: # DECRYPT
        if(cipherContents == "RC4"):
            cipherTextInput = bytes.fromhex(file_contents) #convert hex back into bytes
            decrypted_text = rc4_decrypt(cipherTextInput, rc4key)
            theEncryptedContent = decrypted_text.decode() 
        try:
            UserId = None
            conn = db.connect()
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId')
                else:
                    return "Unauthorized", 401  
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "RC4", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return theEncryptedContent, 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
        
# ------ RC4 METHODS --------------------------
def rc4_encrypt(plaintext, key):
    S = list(range(256))
    j = 0
    key_length = len(key)

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + ord(key[i % key_length])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    ciphertext = bytearray()

    # Pseudo-random generation algorithm (PRGA)
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        ciphertext.append(char ^ k)

    return bytes(ciphertext)

def rc4_decrypt(ciphertext, key):
    S = list(range(256))
    j = 0
    key_length = len(key)

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + ord(key[i % key_length])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    plaintext = bytearray()

    # Pseudo-random generation algorithm (PRGA)
    for char in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        plaintext.append(char ^ k)

    return bytes(plaintext)
# ------------------------------------------------------

@app.route('/DES', methods=['POST'])
def desHandler():
    file_contents=None
    desKey=None
    if('encrypt' not in request.form):
        return "Must include encryption information", 400
    encrypt = True if request.form['encrypt']=="true" else False
    if(not encrypt):
        if('desKey' not in request.form):
            return "Must include key for decryption", 400
        if(request.form['desKey'] == ""):
            return "Must include key for decryption", 400
        desKey = str(request.form['desKey'])
    if(encrypt):
        if('desKey' not in request.form):
            return "Must include key for encryption", 400
        if(request.form['desKey'] == ""):
            return "Must include key for encryption", 400
        desKey = str(request.form['desKey'])
    if('file' in request.files):
        uploaded_file = request.files['file']
        if(not uploaded_file.filename.lower().endswith('.txt')):
            return "Only txt files are accepted, sorry", 400
        file_contents = uploaded_file.read().decode('utf-8')
    elif ('file' in request.form):
        file_contents= request.form['file']
    else:   
        return 'You have to include some content you want to encrypt', 400
    cipherContents = "DES" 
    theEncryptedContent = ""
    if (encrypt): 
        if(cipherContents == "DES"):  
            theEncryptedContent = file_contents + " DES ENCRYPT " + desKey
        try:
            UserId = None
            conn = db.connect() 
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId')
                else:
                    return "Unauthorized", 401  
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "DES", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({"theEncryptedContent":theEncryptedContent, "length": len(file_contents)}), 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
    else: # DECRYPT
        if(cipherContents == "DES"):
            theEncryptedContent = file_contents + " DES ENCRYPT " + desKey
        try:
            UserId = None
            conn = db.connect()
            cursor = conn.cursor()
            try:
                theToken=request.cookies.get("theJSONWebToken")
                cursor.execute("SELECT * FROM BlacklistedTokens WHERE Token = %s", (theToken,))
                rows= cursor.fetchall()
                if(len(rows)==0):
                    decodedToken= jwt.decode(theToken, secretKey, algorithms="HS256")
                    UserId = decodedToken.get('UserId') 
                else:
                    return "Unauthorized", 401 
            except Exception as decodingTokenException:
                print(decodingTokenException)
                return "Unauthorized", 401
            cursor.execute("INSERT INTO DecryptoidUses (InputText, CipherUsed, UserId) VALUES (%s,%s, %s)",(file_contents, "DES", UserId))
            conn.commit()
            cursor.close()
            conn.close()
            return theEncryptedContent, 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500

# ---------------------------------------------

if __name__ == '__main__':
    app.run(debug=True, port=5001)