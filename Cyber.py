import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import time
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import ctypes
import sys

SALT_SIZE = 16  
KEY_SIZE = 32  
ITERATIONS = 100000  

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    
    salt = os.urandom(SALT_SIZE)
    key = generate_key(password, salt)

    with open(file_path, 'rb') as f:
        data = f.read()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"File encrypted and saved to {encrypted_file_path}")

def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, 'rb') as f:
        salt = f.read(SALT_SIZE)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return

    decrypted_file_path = encrypted_file_path[:-4] 
    with open(decrypted_file_path, 'wb') as f:
        f.write(data)

    print(f"File decrypted and saved to {decrypted_file_path}")

MONITORED_FILES = ["file1.txt", "file2.txt"]  
HASH_FILE = "file_hashes.json"  

def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def load_hashes():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def monitor_files():
    stored_hashes = load_hashes()
    current_hashes = {}

    for file_path in MONITORED_FILES:
        file_hash = compute_hash(file_path)
        if file_hash:
            current_hashes[file_path] = file_hash
            if file_path in stored_hashes:
                if stored_hashes[file_path] != file_hash:
                    print(f"File changed: {file_path}")
            else:
                print(f"New file detected: {file_path}")

    save_hashes(current_hashes)

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        print(f"IP Packet: {ip_src} -> {ip_dst}")

        if TCP in packet:
            print(f"TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")

        elif UDP in packet:
            print(f"UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")

        elif ICMP in packet:
            print(f"ICMP Packet: {ip_src} -> {ip_dst}, Type: {packet[ICMP].type}")

def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def run_as_admin():
    if sys.platform.startswith('win'):
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        print("Please run the script as root (e.g., using sudo).")

def start_sniffing(interface=None):
    if not is_admin():
        print("Please run the script as administrator/root!")
        run_as_admin()
        sys.exit()

    print("Starting packet capture on interface:", interface)
    if interface:
        sniff(iface=interface, prn=analyze_packet, store=False)
    else:
        sniff(prn=analyze_packet, store=False)

def main():
 while True:
  first = input("Enter 'fs' for File Storage, or 'fm' for File Monitor, or 'dv' for Data Visualization, or 'q' to quit: ").lower()
  if first == 'fs':
    while True:
        choice = input("Enter 'e' to encrypt or 'd' to decrypt a file, or 'q' to quit: ").lower()
        if choice == 'e':
            file_path = input("Enter the path of the file to encrypt: ")
            password = input("Enter the password: ")
            encrypt_file(file_path, password)
        elif choice == 'd':
            encrypted_file_path = input("Enter the path of the encrypted file: ")
            password = input("Enter the password: ")
            decrypt_file(encrypted_file_path, password)
        elif choice == 'q':
            break
        else:
            print("Invalid choice. Please try again.")
  elif first == 'fm':
   try:
        while True:
            print("Monitoring files for changes...")
            monitor_files()
            time.sleep(10)  
   except KeyboardInterrupt:
         print("File integrity monitor stopped.")
  elif first == 'dv': 
   print("Available network interfaces:", get_if_list())
   interface = input("Enter the network interface to capture on (or leave blank for default): ")
   if interface.strip() == "":
        interface = None
   start_sniffing(interface)

   input("Press Enter to exit...")
  elif first == 'q':
            break
  else:
    print("Invalid choice. Please try again.")
if __name__ == "__main__":
    main()