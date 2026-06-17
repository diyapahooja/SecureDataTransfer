import bcrypt
import json
import os

USER_DB = "users.json"

def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f, indent=2)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "User already exists."
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed.decode('utf-8')
    save_users(users)
    return True, "User registered."

def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User not found."
    stored_hash = users[username].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        return True, "Authentication successful."
    return False, "Invalid password."