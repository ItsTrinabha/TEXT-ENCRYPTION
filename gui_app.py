import tkinter as tk
from crypto_utils import *

def encrypt_text():
    text = plain_entry.get()
    algo = algo_var.get()

    if not text:
        status.set("❌ Enter text to encrypt")
        return

    if algo == "AES":
        data = aes_encrypt(text)

        cipher_var.set(data["cipher"])
        key_var.set(data["key"])
        nonce_var.set(data["nonce"])

        status.set(
            "AES Encryption Done\n"
            "Copy: Cipher + Key + Nonce for decryption"
        )

    elif algo == "DES":
        data = des_encrypt(text)

        cipher_var.set(data["cipher"])
        key_var.set(data["key"])
        nonce_var.set(data["nonce"])

        status.set(
            "DES Encryption Done\n"
            "Copy: Cipher + Key + Nonce for decryption"
        )

    else:  # RSA
        data = rsa_encrypt(text)

        cipher_var.set(data["cipher"])
        key_var.set(data["private_key"])
        nonce_var.set("Not Required")

        status.set(
            "RSA Encryption Done\n"
            "Copy: Cipher + Private Key for decryption"
        )

def decrypt_text():
    algo = algo_var.get()
    cipher = cipher_var.get()
    key = key_var.get()
    nonce = nonce_var.get()

    if not cipher or not key:
        status.set("❌ Cipher and Key required")
        return

    try:
        if algo == "AES":
            plain = aes_decrypt(cipher, key, nonce)
        elif algo == "DES":
            plain = des_decrypt(cipher, key, nonce)
        else:
            plain = rsa_decrypt(cipher, key)

        status.set("🔓 DECRYPTED TEXT:\n" + plain)

    except Exception:
        status.set("❌ Decryption failed (wrong key / data)")

# ---------------- GUI ----------------

root = tk.Tk()
root.title("Cyber Encryption Tool (Correct)")
root.geometry("700x550")

tk.Label(root, text="Plain Text").pack()
plain_entry = tk.Entry(root, width=90)
plain_entry.pack()

algo_var = tk.StringVar(value="AES")
tk.Radiobutton(root, text="AES (Key + Nonce)", variable=algo_var, value="AES").pack()
tk.Radiobutton(root, text="DES (Key + Nonce)", variable=algo_var, value="DES").pack()
tk.Radiobutton(root, text="RSA (Private Key)", variable=algo_var, value="RSA").pack()

tk.Button(root, text="Encrypt", command=encrypt_text).pack(pady=5)

tk.Label(root, text="Cipher Text (COPY THIS)").pack()
cipher_var = tk.StringVar()
tk.Entry(root, textvariable=cipher_var, width=90).pack()

tk.Label(root, text="Key / Private Key (COPY THIS)").pack()
key_var = tk.StringVar()
tk.Entry(root, textvariable=key_var, width=90).pack()

tk.Label(root, text="Nonce (AES/DES only)").pack()
nonce_var = tk.StringVar()
tk.Entry(root, textvariable=nonce_var, width=90).pack()

tk.Button(root, text="Decrypt", command=decrypt_text).pack(pady=5)

status = tk.StringVar()
tk.Label(root, textvariable=status, wraplength=650, fg="blue").pack(pady=10)

root.mainloop()
