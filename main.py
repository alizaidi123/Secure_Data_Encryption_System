import streamlit as stl
import hashlib
from cryptography.fernet import Fernet, InvalidToken

if "stored_data" not in stl.session_state:
    stl.session_state.stored_data = {}

if "login_required" not in stl.session_state:
    stl.session_state.login_required = False

if "failed_attempts" not in stl.session_state:
    stl.session_state.failed_attempts = 0

if "logged_in" not in stl.session_state:
    stl.session_state.logged_in = True


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(Fernet.generate_key())

def encrypt_data(data , passkey):
    fernet = Fernet(Fernet.generate_key())
    encrypted = fernet.encrypt(data.encode())
    return encrypted, fernet

def decrypt_data(encrypted_text , key):
    try:
        return key.decrypt(encrypted_text).decode()
    except InvalidToken:
        return None

def insert_data():
    stl.subheader("Insert Secure Data")
    username = stl.text_input("Username")
    text = stl.text_area("Enter Your Secret Data")
    passkey = stl.text_input("Enter Your Passkey", type="password")

    if stl.button("Encrypt and Store"):
        if username and text and passkey:
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypt_text = fernet.encrypt(text.encode())

            hashed_passkey = hash_passkey(passkey)
            stl.session_state.stored_data[username] = {
                "encrypted_text": encrypt_text.decode(),
                "fernet_key": key.decode(),
                "passkey": hashed_passkey
            }
            stl.success("Data Stored Sucurely")
        else:
            stl.error("All Fields Are Required")
def retrieve_data():
    stl.subheader("🔎 Retrieve Your Data")

    username = stl.text_input("Username")
    passkey = stl.text_input("Enter your passkey", type="password")

    if stl.button("Decrypt"):
        if username not in stl.session_state.stored_data:
            stl.error("No data found for this user.")
            return

        stored = stl.session_state.stored_data[username]
        entered_hash = hash_passkey(passkey)

        if entered_hash != stored["passkey"]:
            stl.session_state.failed_attempts += 1
            stl.warning(f"Invalid passkey! Attempt {stl.session_state.failed_attempts}/3")

            if stl.session_state.failed_attempts >= 3:
                stl.session_state.logged_in = False
                stl.session_state.login_required = True
                stl.rerun()
            return

        fernet = Fernet(stored["fernet_key"].encode())
        decrypted = decrypt_data(stored["encrypted_text"].encode(), fernet)

        if decrypted:
            stl.success("Data Decrypted:")
            stl.code(decrypted)
            stl.session_state.failed_attempts = 0  # reset on success
        else:
            stl.error("Decryption failed!")

def login():
    stl.subheader("🔐 Reauthorization Required")

    username = stl.text_input("Admin Username", key="login_user")
    password = stl.text_input("Admin Password", type="password", key="login_pass")

    if stl.button("Login"):
        if username == "admin" and password == "admin123":
            stl.success("Logged in successfully!")
            stl.session_state.failed_attempts = 0
            stl.session_state.login_required = False
            stl.session_state.logged_in = True
            stl.rerun()
        else:
            stl.error("Invalid credentials")

def home():
    stl.title("Secure Data Encryption System")
    stl.write("Chose an action:")
    option = stl.selectbox("Select:", ["Insert Data", "Retrieve Data"])

    if option == "Insert Data":
        insert_data()
    elif option == "Retrieve Data":
        if stl.session_state.failed_attempts >= 3 or not stl.session_state.logged_in:
            stl.session_state.login_required = True
            login()
        else:
            retrieve_data()

def main():
    if stl.session_state.login_required:
        login()
    else:
        home()

if __name__ == "__main__":
    main()
