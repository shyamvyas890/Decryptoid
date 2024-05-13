# Decryptoid

Welcome to Decryptoid, an application where you can encrypt and decrypt information with the substitution, double transposition, RC4, and DES ciphers. Below, you'll find a detailed guide to the features of our platform.

## Table of Contents
- [Features](#features)
  - [Login, Logout, and Register](#authentication)
  - [Encryption and Decryption](#ciphers)
  - [Input Validation](#validation)
  - [Security Features](#security)

## Features

### Login, Logout, and Register
Users can [register, login, and logout](#authentication) of the application at their chosing. 

### Encryption and Decryption
Encrypt and Decrypt your secrets with either the substitution, double transposition, RC4, or DES [cipher](#ciphers).

### Input Validation
Input is validated on both the client and server side to make sure that it is formatted properly.

### Security Features
- **JSON Web Token Authentication:** JSON Web Tokens Are issued by the server to the client to as a means of authenticating the user. If the user isn't logged in, they are redirected to the login page.
- **HTTP Only Cookies:** JSON Web Tokens are stored securely by the client in an HTTP only cookie to prevent client side JavaScript from accessing it.
- **REST API Authentication:** Protected routes verify that the user has a valid JSON web token, before allowing the user to access the path.
- **Cookie and Token Expiry:** Both the JSON Web token, and the HTTP only cookie are set to expire automatically after 24 hours, which automatically logs users out after 24 hours, for the user's own security.
- **Password Hashing:** All passwords are securely hashed first, before being stored in the MySQL database.

## Technologies Used

Decryptoid is built using the following technologies:

- HTML
- CSS
- JavaScript
- Flask-MySQL
- Bootstrap
- CORS
- Typescript
- React.js
- React Router
- Bcrypt
- Python
- Flask
- JWT (JSONWebToken)

Thank you for your interest in Decryptoid! We appreciate you taking the time to view our work. 

## How to Run This Application

1. Install MySQL Workbench and run the following code in MySQL Workbench: 
```sql 
CREATE DATABASE Decryptoid;
USE Decryptoid;
CREATE TABLE Users(
	UserId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	Username VARCHAR(255) NOT NULL UNIQUE,
	Email VARCHAR(255) NOT NULL UNIQUE,
	PasswordHash VARCHAR(255) NOT NULL
);
CREATE TABLE BlacklistedTokens (
	BlasklistedTokenId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	Token VARCHAR(255) NOT NULL UNIQUE
);
CREATE TABLE DecryptoidUses (
	DecryptoidUseId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	InputText TEXT NOT NULL,
	CipherUsed VARCHAR(500) NOT NULL,
	UsedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	UserId INT NOT NULL,
	FOREIGN KEY (UserId) REFERENCES Users(UserId)
);
```
2. In [app.py](server/app.py) , make sure to modify the MYSQL_DATABASE_HOST, MYSQL_DATABASE_USER, and MYSQL_DATABASE_PASSWORD to match your MySQL credentials:
```python
app.config['MYSQL_DATABASE_HOST'] = 'localhost' 
app.config['MYSQL_DATABASE_USER'] = 'root' 
app.config['MYSQL_DATABASE_PASSWORD'] = 'password' # root for windows   
app.config['MYSQL_DATABASE_DB'] = 'Decryptoid' 
```

3. Modify the "secretKey" in [app.py](server/app.py) to be a complex, random, and unique string, which you should keep a secret and not tell anyone.
```python
secretKey = "secretKey" # Change this
```
4. Install Node.js.
5. Install Python.
6. Download this project repository and open up two terminal or command prompt windows.
7. In the first terminal, run this command:
`cd client`
8. In the second terminal, run this command:
`cd server`
9. Run the following command in the second terminal:
`python -m venv VirtualEnvironment`
10. On the second terminal, if you are running this application on MacOS or Linux, run the first command below, else run the second command.
    1. `source VirtualEnvironment/bin/activate`
    2. `VirtualEnvironment\Scripts\activate`
11. Run the following command in the second terminal:
`pip install -r requirements.txt`
12. Run the following command in the second terminal:
`python app.py`
13. Run the following command in the first terminal:
`npm start` 
14. Now, the application will open up in your browser. Enjoy!
15. When you are done using this application, hit "Ctrl + C" on both terminals and then run this command on both terminals.
`deactivate`