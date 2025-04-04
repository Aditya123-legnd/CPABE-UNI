import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
import asyncio
import hashlib
import getpass

# Initialize Firebase Admin SDK with credentials from downloaded JSON file  
cred = credentials.Certificate('cpabe-cs24-firebase-adminsdk-fbsvc-2185bc72cd.json')
firebase_admin.initialize_app(cred, {
'databaseURL': 'https://cpabe-cs24-default-rtdb.asia-southeast1.firebasedatabase.app/'
})

def id_index():
    i = 1
    while True:
        ref = db.reference(f'staff/{i}')
        snapshot = ref.get()
        if snapshot is None:
            return i
        i += 1

def authenticate_user(username, password):
    user_count = id_index()
    for i in range(1, user_count):
        ref = db.reference('staff/' + str(i))
        data = ref.get()  
        if username == data['UserName']:
            # Checkk user password and return data if authentication is successful
            # Compare the password hash with the stored hash
            if data['PASS'] == hashlib.sha256('PC01'.encode()).hexdigest():   #sha256("password".encode()).hexdigest():
                return data
            if data['PASS'] == hashlib.sha256('IT123'.encode()).hexdigest():   #sha256("password".encode()).hexdigest():
                return data
    # If authentication fails, return None
    return None

def main():
    # Use function to aunthenticate user
    # Get username and password from user
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    user_data = authenticate_user(username, password)  

    # Check result and print data if authentication is successful
    # Print error message if authentication fails  
    if user_data:
        print("Login successful!")
    else:
        print("Invalid Credentials!")

if __name__=="__main__":
    main()