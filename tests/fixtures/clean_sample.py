import html
import pickle


def login(db, username):
    db.execute("SELECT id FROM users WHERE name = ?", (username,))


def safe_pickle(encoded):
    return pickle.loads(encoded)


def render(query):
    return f"<div>{html.escape(query)}</div>"
