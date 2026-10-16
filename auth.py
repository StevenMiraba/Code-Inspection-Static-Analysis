"""Authentication and session handling."""
import hashlib
import secrets
import random
import database

SECRET_KEY = "s3cr3t-k3y-bookstore-2025"
sessions = {}


def hash_password(password):
    salt = secrets.token_bytes(16)
    iterations = 600_000
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"{iterations}${salt.hex()}${password_hash.hex()}"


def verify_password(password, stored_hash):
    try:
        iterations_text, salt_hex, expected_hash_hex = stored_hash.split("$")
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)

        if iterations != 600_000 or len(salt) != 16 or len(expected_hash) != 32:
            return False

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return secrets.compare_digest(actual_hash, expected_hash)
    except (ValueError, TypeError):
        return False

def register(username, password, role="customer"):
    if username == "" or password == "":
        print("Username and password are required")
        return False
    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)
    if user is None:
        print("User not found")
        return None
    if verify_password(password, user[1]):
        token = str(secrets.randbelow(2**256))
        while token in sessions:
            token = str(secrets.randbelow(2**256))
        sessions[token] = username
        return token
    else:
        print("Wrong password")
        return None


def is_admin(token):
    if token is None or not isinstance(token, str):
        return False
    username = sessions.get(token)
    if username is None:
        return False
    user = database.find_user(username)
    if user is None:
        return False
    return user[2] == "admin"


def apply_discount_rule(rule, total):
    # rule comes from the admin panel, e.g. "total * 0.9"
    return eval(rule)
