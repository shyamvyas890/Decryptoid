from flask import Flask, request, jsonify, make_response
from flaskext.mysql import MySQL
import bcrypt, jwt, datetime, math, re
from datetime import timezone
from flask_cors import CORS
import random



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
    
    if('encrypt' not in request.form):
        return "Must include encryption information", 400
    encrypt = True if request.form['encrypt']=="true" else False
    if(not encrypt):
        if('desKey' not in request.form):
            return "Must include key for decryption", 400
        if(request.form['desKey']==""):
            return "Must include key for decryption", 400
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
    desKey=""
    

    if (encrypt): 
        if(cipherContents == "DES"):  

            desKey = generate64BitKey()
            hexadesKey = bin2hex(desKey)
            desKey = permute(desKey, keyp, 56)
            
            # Split key 
            left = desKey[0:28]    
            right = desKey[28:56]  
            
            roundKeyBinary = []
            for i in range(0, 16):
                left = shift_left(left, bit_rotation_table[i])
                right = shift_left(right, bit_rotation_table[i])
                combine_str = left + right
                round_key = permute(combine_str, key_compression, 48)
                roundKeyBinary.append(round_key)

            plaintext = file_contents
            cipher_text = desEncrypt(plaintext, roundKeyBinary)
            theEncryptedContent = cipher_text
            
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
            return jsonify({"theEncryptedContent":theEncryptedContent, "desKey": hexadesKey}), 200
        except Exception as e:
            print(e)
            return "Internal Server Error", 500
    else: #DECRYPT
        if cipherContents == "DES":
            
            desKey = request.form.get('desKey')
            desKey = hex2bin(desKey)
            desKey = permute(desKey, keyp, 56)
            
            left = desKey[0:28]
            right = desKey[28:56]
            
            roundKeyBinary = []
            for i in range(0, 16):
                left = shift_left(left, bit_rotation_table[i])
                right = shift_left(right, bit_rotation_table[i])
                combine_str = left + right
                round_key = permute(combine_str, key_compression, 48)
                roundKeyBinary.append(round_key)
            
            # Reverse the round keys for decryption
            rkb_rev = roundKeyBinary[::-1]
            
            ciphertext = file_contents
            decrypted_text = desDecrypt(ciphertext, rkb_rev)
            theEncryptedContent = decrypted_text

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

# --------------------------------------------------
# STANDARD DES tables (from Geeks4Geeks DES Set 1)
#________________KEY GENERATION________________________
#
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Number of key bits shifted per round (from round 1->16)
bit_rotation_table = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# reduce 56-bit key into 48 bits (compression permutation)
key_compression = [14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32]
#________________________________________________________

# Initial permutation
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion permutation table 
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# P-box permutation
per = [16,  7, 20, 21, 29, 12, 28, 17,
       1, 15, 23, 26, 5, 18, 31, 10,
       2,  8, 24, 14, 32, 27,  3,  9,
       19, 13, 30,  6, 22, 11,  4, 25]

# 8 Substitution boxes (S-box) Tables
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# final permutation (IP-1)
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]
# _____________________________________________________________________________
# __________________________HELPER FUNCTIONS___________________________________
# _____________________________________________________________________________

def plaintext_to_hex(plaintext):
    hex_string = plaintext.encode('utf-8').hex().upper()
    return hex_string

# Pad plaintext to make it a multiple of 8 
def pad_plaintext(plaintext):
    padding_len = 8 - (len(plaintext) % 8)
    if padding_len != 8:
        plaintext += chr(padding_len) * padding_len
    return plaintext

#random 64 bit key for DES - will be provided to the user for decryption 
def generate64BitKey():
    random_bits = [random.choice(['0', '1']) for _ in range(64)]
    random_key = ''.join(random_bits)
    return random_key

# Hexadecimal String to Binary
def hex2bin(hexadecimalString):
    hex2BinMapping = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
                      '4': "0100", '5': "0101", '6': "0110", '7': "0111", 
                      '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
                      'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    bin = ""
    for i in range(len(hexadecimalString)):
        bin = bin + hex2BinMapping[hexadecimalString[i]]
    return bin
 
# Binary to hexadecimal conversion
def bin2hex(binaryString):
    bin2HexMapping = {"0000": '0', "0001": '1',"0010": '2',"0011": '3',
                      "0100": '4',"0101": '5',"0110": '6',"0111": '7',
                      "1000": '8',"1001": '9',"1010": 'A',"1011": 'B',
                      "1100": 'C',"1101": 'D',"1110": 'E',"1111": 'F'}
    hex = ""
    # map hex for every 4 binary
    for i in range(0, len(binaryString), 4):
        ch = ""
        ch = ch + binaryString[i]
        ch = ch + binaryString[i + 1]
        ch = ch + binaryString[i + 2]
        ch = ch + binaryString[i + 3]
        hex = hex + bin2HexMapping[ch]
    return hex
 
# Binary to decimal conversion``
def bin2dec(binary):
    return int(str(binary), 2)

# Decimal to binary conversion
def dec2bin(num): 
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

# Permute function to rearrange the bits
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation
 
# shifting the bits towards left by nth shifts
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k
 
# XOR A and B 
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans

def desEncrypt(plaintext, roundKeyBinary):
    plaintext = pad_plaintext(plaintext)
    hex_plaintext = plaintext_to_hex(plaintext)
    
    cipher_text = ""
    for i in range(0, len(hex_plaintext), 16):
        block = hex_plaintext[i:i+16]
        block_binary = hex2bin(block)
        block_binary = permute(block_binary, initial_perm, 64)
        
        left = block_binary[0:32]
        right = block_binary[32:64]
        
        for j in range(0, 16):
            #  Expansion D-box: Expanding the 32 bits data into 48 bits
            right_expanded = permute(right, exp_d, 48)
            
            # XOR RoundKey[j] and right_expanded
            xor_x = xor(right_expanded, roundKeyBinary[j])
            
            # S-boxex: substituting the value from s-box table by calculating row and column
            sbox_str = ""
            for k in range(0, 8):
                row = bin2dec(int(xor_x[k * 6] + xor_x[k * 6 + 5]))
                col = bin2dec(int(xor_x[k * 6 + 1] + xor_x[k * 6 + 2] + xor_x[k * 6 + 3] + xor_x[k * 6 + 4]))
                val = sbox[k][row][col]
                sbox_str = sbox_str + dec2bin(val)
            
            # Straight D-box: After substituting rearranging the bits
            sbox_str = permute(sbox_str, per, 32)
            
            # XOR left and sbox_str
            result = xor(left, sbox_str)
            left = result
            
            # Swapper
            if j != 15:
                left, right = right, left
        
        # Combination 
        combine = left + right 
        
        # Final permutation: final rearranging of bits to get cipher text
        cipher_text += bin2hex(permute(combine, final_perm, 64))
    
    return cipher_text


def desDecrypt(ciphertext, roundKeyBinaryReverse):
    plaintext_hex = ""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        block_binary = hex2bin(block)
        block_binary = permute(block_binary, initial_perm, 64)
        
        left = block_binary[0:32]
        right = block_binary[32:64]
        
        for j in range(0, 16):
            # Expansion D-box
            right_expanded = permute(right, exp_d, 48)
            
            # XOR with round key
            xor_x = xor(right_expanded, roundKeyBinaryReverse[j])
            
            # S-boxes
            sbox_str = ""
            for k in range(0, 8):
                row = bin2dec(int(xor_x[k * 6] + xor_x[k * 6 + 5]))
                col = bin2dec(int(xor_x[k * 6 + 1] + xor_x[k * 6 + 2] + xor_x[k * 6 + 3] + xor_x[k * 6 + 4]))
                val = sbox[k][row][col]
                sbox_str = sbox_str + dec2bin(val)
            
            # D-box
            sbox_str = permute(sbox_str, per, 32)
            
            # XOR
            result = xor(left, sbox_str)
            left = result
            
            # Swap
            if j != 15:
                left, right = right, left
        
        # Combination + permutate
        combine = left + right
        plaintext_hex += bin2hex(permute(combine, final_perm, 64))
    
    plaintext = bytes.fromhex(plaintext_hex).decode('utf-8')
    padding_len = ord(plaintext[-1])
    plaintext = plaintext[:-padding_len]
    
    return plaintext
#----------------------END OF DES METHODS ----------------------------------

if __name__ == '__main__':
    app.run(debug=True, port=5001)