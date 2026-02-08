from flask import Flask, render_template, request
from crypto_utils import *

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    encrypted = None
    decrypted = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        algo = request.form.get("algo")

        try:
            # ---------- ENCRYPT ----------
            if action == "encrypt":
                plain = request.form.get("plain")

                if not plain:
                    error = "Enter text to encrypt"

                elif algo == "AES":
                    encrypted = aes_encrypt(plain)

                elif algo == "DES":
                    encrypted = des_encrypt(plain)

                elif algo == "RSA":
                    encrypted = rsa_encrypt(plain)

            # ---------- DECRYPT ----------
            elif action == "decrypt":
                cipher = request.form.get("cipher")
                key = request.form.get("key")
                nonce = request.form.get("nonce")

                if not cipher or not key:
                    error = "Cipher and Key are required"

                else:
                    if algo == "AES":
                        decrypted = aes_decrypt(cipher, key, nonce)

                    elif algo == "DES":
                        decrypted = des_decrypt(cipher, key, nonce)

                    elif algo == "RSA":
                        decrypted = rsa_decrypt(cipher, key)

        except Exception:
            error = "Decryption failed (wrong key / data)"

    return render_template(
        "index.html",
        encrypted=encrypted,
        decrypted=decrypted,
        error=error
    )

if __name__ == "__main__":
    app.run(debug=True)
