from pathlib import Path
import base64
import pickle
import subprocess


def login(db, username, password):
    query = f"SELECT id FROM users WHERE name='{username}' AND password='{password}'"
    db.execute(query)


def decode_payload(encoded):
    return pickle.loads(base64.b64decode(encoded))


def run_command(command):
    return subprocess.run(command, shell=True)


def render(query):
    return f"<div>results for {query}</div>"
