import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
import pyrebase
import hashlib
import json
import getpass

#Configure and Connext to Firebase

firebaseConfig = {'apiKey': "AIzaSyD2BQeAVtXQlwuyMS7fW1TfwCDf7tKWGHc",
  'authDomain': "cpabe-cs24.firebaseapp.com",
  'databaseURL': "https://cpabe-cs24-default-rtdb.asia-southeast1.firebasedatabase.app",
  'projectId': "cpabe-cs24",
  'storageBucket': "cpabe-cs24.firebasestorage.app",
  'messagingSenderId': "183481204156",
  'appId': "1:183481204156:web:f7f4eb72b72ca1e6afbfb9",
  'measurementId': "G-W1ER02HCV8"}

firebase=pyrebase.initialize_app(firebaseConfig)
auth=firebase.auth()
dab = firebase.database()

#Login function

def id_index():
    i = 1
    while True:
        ref = db.reference(f'staff/{i}')
        snapshot = ref.get()
        if snapshot is None:
            return i
        i += 1

def authenticate_user(username, password):
    # Initialize Firebase Admin SDK with credentials from downloaded JSON file  
    cred = credentials.Certificate('cpabe-cs24-firebase-adminsdk-fbsvc-2185bc72cd.json')
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://cpabe-cs24-default-rtdb.asia-southeast1.firebasedatabase.app/'
    })
    user_count = id_index()
    for i in range(1, user_count):
        ref = db.reference('staff/' + str(i))
        data = ref.get()
        if username == data['UserName']:
            # Check user password and return data if authentication is successful
            if data['PASS'] == hashlib.sha256(password.encode()).hexdigest():
                return data
    # If authentication fails, return None
    return None

def login():
    print("Log in...")
    email=input("Enter email: ")
    password=input("Enter password: ")
    try:
        login = auth.sign_in_with_email_and_password(email, password)
        user_id = login['localId']
        print("Successfully logged in!")
            # print(auth.get_account_info(login['idToken']))
            # email = auth.get_account_info(login['idToken'])['users'][0]['email']
            # print(email)
        # Check if user is admin
        admin = dab.child("admin").get()
        admin_id = admin.val().get("id")
        if user_id == admin_id:
            # User is admin, return data
            data = dab.child("admin_data").get().val()
            print("Welcome admin!")
            print(data)
        else:
            # User is not admin, do something else
            print("Welcome user!")
            user_data = authenticate_user(email, password)
            if user_data:
                with open('user.json', 'w', encoding='utf-8') as f:
                    json.dump(user_data, f, ensure_ascii=False, indent=4)
                print("Success")
            else:
                print("Incorrect login information!")
    except:
        print("Invalid email or password")
    return

#Signup Function

def signup():
    print("Sign up...")
    email = input("Enter email: ")
    password=input("Enter password: ")
    try:
        user = auth.create_user_with_email_and_password(email, password)
        ask=input("Do you want to login?[y/n]")
        if ask=='y':
            login()
    except: 
        print("Email already exists")
    return

#Main

ans=input("Are you a new user?[y/n]")

if ans == 'n':
    login()
elif ans == 'y':
    signup()

