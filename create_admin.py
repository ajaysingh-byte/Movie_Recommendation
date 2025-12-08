# create_admin.py
import os
import getpass
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import errorcode
from flask_bcrypt import Bcrypt
from flask import Flask

# Load env
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "movie_app")

def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        auth_plugin="mysql_native_password"
    )

# Use a short Bcrypt using Flask's wrapper
app = Flask(__name__)
bcrypt = Bcrypt(app)

def create_admin(username="admin", email="admin@example.com"):
    print("Create admin account.")
    pw = getpass.getpass("Admin password (input hidden): ")
    confirm = getpass.getpass("Confirm password: ")
    if pw != confirm:
        print("Passwords do not match.")
        return
    pw_hash = bcrypt.generate_password_hash(pw).decode("utf-8")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s LIMIT 1", (username, email))
        if cursor.fetchone():
            print("Admin with that username/email already exists.")
            cursor.close()
            conn.close()
            return
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, 'admin')",
            (username, email, pw_hash)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Admin created: username={username}, email={email}")
    except mysql.connector.Error as e:
        print("MySQL error:", e)
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    create_admin()
