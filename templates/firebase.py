import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth

# Initialize Firebase Admin SDK
cred = credentials.Certificate("path/to/serviceAccountKey.json")  # Replace with the path to your service account key JSON file
firebase_admin.initialize_app(cred)

# Function to get user data
def get_user_data(user_id):
    try:
        user = auth.get_user(user_id)
        return user.to_dict()
    except auth.AuthError as e:
        print(f"Error fetching user data: {e}")
        return None

# Example usage
user_id = "user_id_here"
user_data = get_user_data(user_id)
if user_data:
    print("User Data:", user_data)
else:
    print("User data not found or error occurred.")
