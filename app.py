import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time
import base64

# Initialize session state variables if they don't exit
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Register'
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'is_registered' not in st.session_state:
    st.session_state.is_registered = False
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0


# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())

# Function to encrypt data
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id):
    try:
        # Check if the passkey matches
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            # Increment failed attempts
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception as e:
        # if decryption fails, increment failed attempts
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

# Function to generate a unique ID for data
def generate_data_id():
    import uuid
    return str(uuid.uuid4())

# Function to reset failed attempts
def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# Function to change page
def change_page(page):
    st.session_state.current_page = page 

# Streamlit UI
# --- Home Page ---
st.title("🔐 Secure Data Encryption System")
# Display current page

# Register page 
if st.session_state.current_page == 'Register':
    st.title('🔐 Register')
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Register"):
        if username and password:
            st.session_state.registered_username = username
            st.session_state.registered_password = password
            st.session_state.is_logged_in = True
            st.session_state.current_page = 'Login'
            st.success("Registered Successfully🎊🎉")
            st.rerun()

        else:
            st.error("🚩 Please enter both fields ❗")

# Login  Page
elif st.session_state.current_page == "Login":
    st.title("📰 Login")
    name = st.text_input("Your Name")
    password = st.text_input("Your Password")
    if st.button("Login"):
        if name and password:
            if name == st.session_state.get("registered_username") and password == st.session_state.get("registered_password"):
                st.session_state.is_registered = True
                st.session_state.current_page = "Home"
                st.success(f"Welcome, {name}!")
                st.rerun()
            else:
                st.error("🚩Invalid Credentials. Please try again")
        else:
            st.error("🚩 Please enter both fields ❗")



# Navigation Sidebar
if st.session_state.is_logged_in and st.session_state.is_registered:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
    
    if choice == "Logout":
        for key in st.session_state.keys():
            del st.session_state[key]
        st.rerun()

    # Home Pgae 
    elif choice == "Home":
        st.sidebar.markdown("Welcome to the Secure Data System")
        st.write("Use this app to ***securely store and retrive data*** using unique passkeys. ")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Store New Data",use_container_width=True):
                change_page("Store Data")
        with col2:
            if st.button("Retrieve Data", use_container_width=True):
                change_page("Retrieve Data")

        # Display stored data count
        st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries.")

    # Store Data
    elif choice == "Store Data":
        st.subheader("Store Data Securely")
        user_data = st.text_area("Enter Data: ")
        passkey = st.text_input("Enter Passkey:",type="password")
        confirm_passkey = st.text_input("Confirm passkey: ", type="password")
        
        if st.button("Encrypt & Save"):
            if user_data and passkey and confirm_passkey:
                if passkey != confirm_passkey:
                    st.error("Passkeys do not match!")
                else:
                    # Generate a unique ID for this data
                    data_id = generate_data_id()

                    # Hash the passkey
                    hashed_passkey = hash_passkey(passkey)

                    # Encrypt the data
                    encrypted_text = encrypt_data(user_data, passkey)

                    # Store in the required format
                    st.session_state.stored_data[data_id] = {
                        "encrypted_text":encrypted_text,
                        "passkey" : hashed_passkey
                    }

                    st.success("Data stored securely!")

                    # Display the data ID for retrival
                    st.code(data_id, language="text")
                    st.info("Save this Data ID! You'll need it to retrieve your data.")
            else:
                st.error("All fields are required!")

    # Retrieve Page
    elif choice == "Retrieve Data":
        st.subheader("Retrieve Your Data")

        # Show attempts remaining
        if st.session_state.failed_attempts >=3:
            time_since_last_attempts = time.time() - st.session_state.last_attempts_time
            lockout_seconds = 5
            
            if time_since_last_attempts < lockout_seconds:
                st.warning("Too many failed attempts! Redirecting to Home Page")
                if st.button("Home", use_container_width=True):
                    change_page("Home")

            else: 
                reset_failed_attempts()

        attempts_remaining = 3 - st.session_state.failed_attempts
        st.info(f"Total Attempts: {attempts_remaining}")

        data_id = st.text_input("Enter Data ID: ")
        passkey = st.text_input("Enter Passkey: ", type="password")

        if st.button("Decrypt"):
            if data_id and passkey:
                if data_id in st.session_state.stored_data:
                    encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                    stored_hash = st.session_state.stored_data[data_id]["passkey"]

                    if hash_passkey(passkey) == stored_hash:
                        decrypted_text = decrypt_data(encrypted_text, passkey , data_id)
                        st.success("Decryption successful!")
                        st.markdown("### Your decrypted Data:")
                        st.code(decrypted_text, language="text")
                    else:
                        st.session_state.failed_attempts += 1
                        st.session_state.last_attempts_time = time.time()
                        attempts_remaining = 3 - st.session_state.failed_attempts
                        st.error(f"Incorrect passkey! Attempts remaining  {attempts_remaining}")

                else:
                    st.error("Data ID not found!")
                    
            else:
                st.error("Both Fields are required! ")

# Add a footer
st.markdown("------")
st.markdown("By Asfaa Khan")
st.markdown("Secure Data Encryption System | Educational Project")
