import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import os

# AES Block size is 16 bytes (128 bits)
BLOCK_SIZE = 16

# Function to pad data to be a multiple of BLOCK_SIZE
def pad(data):
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * b'\0'

# Function to remove padding
def unpad(data):
    return data.rstrip(b'\0')

# Function to generate a 256-bit AES key from the password using scrypt
def generate_key(password):
    salt = os.urandom(16)  # Random salt for key generation
    key = scrypt(password.encode(), salt, dklen=32, N=2**14, r=8, p=1)  # AES-256 (32 bytes key)
    return key, salt

# Function to encrypt a file
def encrypt_file(input_file, password, output_file):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        key, salt = generate_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(data))

        with open(output_file, 'wb') as f:
            f.write(salt)  # Store salt for key regeneration during decryption
            f.write(cipher.iv)  # Store the initialization vector
            f.write(ciphertext)

        messagebox.showinfo("Success", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to decrypt a file
def decrypt_file(input_file, password, output_file):
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(16)  # Read the salt from the beginning of the file
            iv = f.read(16)  # Read the IV (Initialization Vector)
            ciphertext = f.read()

        # Re-generate the key using the same salt and password
        key = scrypt(password.encode(), salt, dklen=32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext))

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", "File decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# GUI Functions
def select_file_to_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_var.set(file_path)

def select_file_to_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        input_file_var.set(file_path)

def save_encrypted_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        output_file_var.set(file_path)

def save_decrypted_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
    if file_path:
        output_file_var.set(file_path)

def encrypt():
    input_file = input_file_var.get()
    password = password_var.get()
    output_file = output_file_var.get()

    if not input_file or not password or not output_file:
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    encrypt_file(input_file, password, output_file)

def decrypt():
    input_file = input_file_var.get()
    password = password_var.get()
    output_file = output_file_var.get()

    if not input_file or not password or not output_file:
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    decrypt_file(input_file, password, output_file)

# GUI Setup
root = tk.Tk()
root.title("File Encryption/Decryption Tool")
root.geometry("450x400")
root.config(bg="#f7f7f7")

# Center the window on the screen
window_width = 450
window_height = 400
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
position_top = int(screen_height / 2 - window_height / 2)
position_left = int(screen_width / 2 - window_width / 2)
root.geometry(f'{window_width}x{window_height}+{position_left}+{position_top}')

# Add some padding to the interface
padx = 10
pady = 10

# Frame for the input fields
frame = ttk.Frame(root, padding="20")
frame.grid(row=0, column=0, sticky="nsew", padx=padx, pady=pady)

# Input File Selection
input_file_var = tk.StringVar()
output_file_var = tk.StringVar()
password_var = tk.StringVar()

tk.Label(frame, text="Select File to Encrypt/Decrypt", font=("Arial", 12)).grid(row=0, column=0, sticky="w", pady=5)
tk.Entry(frame, textvariable=input_file_var, width=35, font=("Arial", 10)).grid(row=1, column=0, pady=5)
tk.Button(frame, text="Browse", command=select_file_to_encrypt, width=15, relief="solid", font=("Arial", 10)).grid(row=1, column=1, padx=5)

tk.Label(frame, text="Password (for AES Key)", font=("Arial", 12)).grid(row=2, column=0, sticky="w", pady=5)
tk.Entry(frame, textvariable=password_var, show="*", width=35, font=("Arial", 10)).grid(row=3, column=0, pady=5)

tk.Label(frame, text="Output File", font=("Arial", 12)).grid(row=4, column=0, sticky="w", pady=5)
tk.Entry(frame, textvariable=output_file_var, width=35, font=("Arial", 10)).grid(row=5, column=0, pady=5)
tk.Button(frame, text="Save Encrypted", command=save_encrypted_file, width=15, relief="solid", font=("Arial", 10)).grid(row=5, column=1, padx=5)

# Buttons for Encrypt/Decrypt
button_frame = ttk.Frame(root, padding="20")
button_frame.grid(row=1, column=0, sticky="nsew", padx=padx, pady=pady)

tk.Button(button_frame, text="Encrypt File", command=encrypt, width=20, relief="solid", font=("Arial", 12), background="#4CAF50", foreground="white").grid(row=0, column=0, padx=10, pady=5)
tk.Button(button_frame, text="Decrypt File", command=decrypt, width=20, relief="solid", font=("Arial", 12), background="#f44336", foreground="white").grid(row=0, column=1, padx=10, pady=5)

# Final touch: Set window to be resizable and update the layout
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_columnconfigure(0, weight=1)

root.mainloop()
