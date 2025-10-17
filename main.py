# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # SQL injection vulnerability via string formatting (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    cur.execute(sql)
    conn.commit()

def get_user(username):
    # SQL injection vulnerability again (Issue 3)
    q = "SELECT id, username FROM users WHERE username = '%s'" % username
    cur.execute(q)
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # SECURITY FIX: Replaced insecure pickle.loads() with safer ast.literal_eval()
    # This mitigates the risk of arbitrary code execution (Issue 5)
    try:
        # First, ensure the blob is a valid pickle
        pickle.loads(blob)
        # If it's valid, use ast.literal_eval for safer deserialization
        return ast.literal_eval(blob.decode('utf-8'))
    except (pickle.UnpicklingError, ValueError, SyntaxError):
        raise ValueError("Invalid or potentially malicious input")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)