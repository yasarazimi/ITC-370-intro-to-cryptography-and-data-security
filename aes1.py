import subprocess
from tkinter import Tk, Label, Button, Entry, Text, END, messagebox
from Cryptodome.Cipher import AES
import binascii


# Function to pad the data as per ISO 10126 standard
def pad_ISO10126(data, block_size):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


# Function to unpad the data as per ISO 10126 standard
def unpad_ISO10126(data):
    padding_len = data[-1]
    if padding_len >= 1 and padding_len <= 16:
        return data[:-padding_len]
    return data


# Function to encrypt the message using AES in ECB mode
def encrypt_AES_ECB(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_ECB)
    msg_padded = pad_ISO10126(msg, AES.block_size)
    ciphertext = aesCipher.encrypt(msg_padded)
    return ciphertext


# Function to decrypt the message using AES in ECB mode
def decrypt_AES_ECB(encryptedMsg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_ECB)
    decrypted_msg_padded = aesCipher.decrypt(encryptedMsg)
    return unpad_ISO10126(decrypted_msg_padded)


# Function to handle the encryption process
def encrypt_message():
    plaintext = plaintext_entry.get().encode('utf-8')
    key = key_entry.get().encode('utf-8')

    # Check if key length is 16 bytes
    if len(key) == 16:
        encrypted = encrypt_AES_ECB(plaintext, key)
        encrypted_text.delete(1.0, END)
        encrypted_text.insert(END, binascii.hexlify(encrypted).decode('utf-8'))
        key_hex_text.delete(1.0, END)
        key_hex_text.insert(END, binascii.hexlify(key).decode('utf-8'))
    else:
        messagebox.showerror("Error", "Key must be 16 bytes (128 bits) long.")


# Function to handle the decryption process
def decrypt_message():
    try:
        encrypted = binascii.unhexlify(encrypted_text.get(1.0, END).strip())
        key = key_entry.get().encode('utf-8')
        decrypted = decrypt_AES_ECB(encrypted, key)
        decrypted_text.delete(1.0, END)
        decrypted_text.insert(END, decrypted.decode('utf-8'))
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Create the main window
root = Tk()
root.title("AES Encryption/Decryption Tool")

# Create and place widgets for plaintext input
Label(root, text="Plaintext:").grid(row=0, column=0, sticky='w')
plaintext_entry = Entry(root, width=50)
plaintext_entry.grid(row=0, column=1, sticky='ew')

# Create and place widgets for key input
Label(root, text="Key (16 bytes):").grid(row=1, column=0, sticky='w')
key_entry = Entry(root, width=50)
key_entry.grid(row=1, column=1, sticky='ew')

def open_website():
    try:
        url = "https://the-x.cn/en-US/cryptography/Aes.aspx"
        subprocess.Popen(['start', url], shell=True)
    except Exception as e:
        messagebox.showerror("Error", "Failed to open website: " + str(e))
# Buttons for encrypting and decrypting
Button(root, text="Encrypt", command=encrypt_message).grid(row=2, column=0, sticky='ew')
Button(root, text="Decrypt", command=decrypt_message).grid(row=2, column=1, sticky='ew')
Button(root, text="Check Online", command=open_website).grid(row=3, column=1, sticky='ew')




# Text area for displaying encrypted message
Label(root, text="Encrypted Message:").grid(row=3, column=0, columnspan=2, sticky='w')
encrypted_text = Text(root, height=5, width=50)
encrypted_text.grid(row=4, column=0, columnspan=2, sticky='ew')
encrypted_text.insert(END, "# thisisfirstproject\n# aesisusedforencr")

# Text area for displaying decrypted message
Label(root, text="Decrypted Message:").grid(row=5, column=0, columnspan=2, sticky='w')
decrypted_text = Text(root, height=5, width=50)
decrypted_text.grid(row=6, column=0, columnspan=2, sticky='ew')

# Text area for displaying the key in hexadecimal format
Label(root, text="Key in Hex:").grid(row=7, column=0, columnspan=2, sticky='w')

key_hex_text = Text(root, height=2, width=50)
key_hex_text.grid(row=8, column=0, columnspan=2, sticky='ew')
Label(root, text="Shahzada Masood, Yasar, Maryam - AUAF 2023").grid(row=9, column=0, columnspan=2, sticky='w')

# Start the GUI event loop
root.mainloop()
