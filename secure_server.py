import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

AES_KEY = b'a_different_key_' 
HMAC_KEY = b'a_very_secret_hmac_key_32_bytes'

app = Flask(__name__)
CORS(app) 

@app.route("/encrypt-secure", methods=['POST'])
def encrypt_secure():
    try:
        plaintext = request.json['plaintext'].encode('utf-8')
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext_raw = encryptor.update(padded_data) + encryptor.finalize()

        h = hmac.HMAC(HMAC_KEY, SHA256(), backend=default_backend())
        h.update(iv)
        h.update(ciphertext_raw)
        mac_tag = h.finalize()

        return jsonify({
            "iv_hex": iv.hex(),
            "ciphertext_hex": ciphertext_raw.hex(),
            "mac_hex": mac_tag.hex(),
            "note": "This payload is now authenticated."
        }), 200

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route("/decrypt-secure", methods=['POST'])
def decrypt_secure():
    try:
        data = request.json
        iv = bytes.fromhex(data['iv_hex'])
        ciphertext = bytes.fromhex(data['ciphertext_hex'])
        received_mac = bytes.fromhex(data['mac_hex'])

        h = hmac.HMAC(HMAC_KEY, SHA256(), backend=default_backend())
        h.update(iv)
        h.update(ciphertext)
        calculated_mac = h.finalize()

        if not hmac.compare_digest(calculated_mac, received_mac):
            return jsonify({"status": "ERROR", "oracle_response": "MAC_INVALID"}), 400

        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return jsonify({
            "status": "OK", 
            "message": "Decryption Successful (MAC was valid)",
            "plaintext": plaintext.decode('utf-8')
        }), 200

    except KeyError:
        return jsonify({"status": "ERROR", "oracle_response": "MAC_MISSING"}), 400
    except ValueError as e:
        return jsonify({"status": "ERROR", "oracle_response": "INVALID_DATA_FORMAT"}), 400
    except Exception as e:
        return jsonify({"status": "ERROR", "oracle_response": str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
