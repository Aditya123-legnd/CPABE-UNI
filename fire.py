import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
import hashlib

# Initialize Firebase Admin SDK with credentials from downloaded JSON file  
cred = credentials.Certificate('cpabe-cs24-firebase-adminsdk-fbsvc-2185bc72cd.json')
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://cpabe-cs24-default-rtdb.asia-southeast1.firebasedatabase.app/'
})

# Get a reference to 'users' node in Realtime Database
ref = db.reference('staff')

# Get data from 'users' node 
data = ref.get()

# Print out the fetched data
print(data)