from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import datetime
import json
import os



class CryptoService:
    def __init__(self, key_storage_path="keys"):
        self.key_storage_path = key_storage_path
        if not os.path.exists(key_storage_path):
            os.makedirs(key_storage_path)

    def save_key(self, key_name, key, master_password):
        master_salt = os.urandom(16)

        key_master_password = self.generate_key(master_password, master_salt)

        aegcm = AESGCM(key_master_password)
        nonce = os.urandom(12)
        encrypted_key = aegcm.encrypt(nonce, key, None)

        key_info = {
            'key_name': key_name,
            'created_on': datetime.datetime.now().isoformat(),
            'master_salt': base64.b64encode(master_salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
        }

        filepath = os.path.join(self.key_storage_path, f"{key_name}.json")
        with open(filepath, 'w') as file:
            json.dump(key_info, file)

        return key_info

    def load_key(self, key_name, master_password):
        filepath = os.path.join(self.key_storage_path, f"{key_name}.json")
        with open(filepath, 'r') as file:
            key_info = json.load(file)

        master_salt = base64.b64decode(key_info['master_salt'])
        nonce = base64.b64decode(key_info['nonce'])
        encrypted_key = base64.b64decode(key_info['encrypted_key'])

        key_master_password = self.generate_key(master_password, master_salt)

        aegcm = AESGCM(key_master_password)
        key = aegcm.decrypt(nonce, encrypted_key, None)

        return key

    def share_key(self, key_name, master_password, recipient_password):
        key = self.load_key(key_name, master_password)
        salt = os.urandom(16)
        key_recipient_password = self.generate_key(recipient_password, salt)

        aegcm = AESGCM(key_recipient_password)
        nonce = os.urandom(12)
        encrypted_key = aegcm.encrypt(nonce, key, None)

        package = {
            'original_key_name': key_name,
            'created_on': datetime.datetime.now().isoformat(),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode()
        }

        json_str = json.dumps(package)
        package_b64 = base64.b64encode(json_str.encode())

        return package_b64

    def receive_key(self, package_b64, recipient_password, new_key_name, master_password):
        package_str = base64.b64decode(package_b64).decode()
        package = json.loads(package_str)

        salt = base64.b64decode(package['salt'])
        nonce = base64.b64decode(package['nonce'])
        encrypted_key = base64.b64decode(package['encrypted_key'])

        key_recipient_password = self.generate_key(recipient_password, salt)

        aegcm = AESGCM(key_recipient_password)
        key = aegcm.decrypt(nonce, encrypted_key, None)

        key_info = self.save_key(new_key_name, key, master_password)

        return {
            'key_name': new_key_name,
            'original_name': package.get('original_key_name'),
            'imported_on': datetime.datetime.now().isoformat()
        }


    def encrypt(self, text, key):
        aegcm = AESGCM(key)
        nonce = os.urandom(12)
        cipherText = aegcm.encrypt(nonce, text.encode('utf-8'), None)

        combined = nonce + cipherText
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_b64, key):
        combined = base64.b64decode(encrypted_b64)
        nonce = combined[:12]
        cipherText = combined[12:]

        aegcm = AESGCM(key)
        text = aegcm.decrypt(nonce, cipherText, None)
        return text.decode('utf-8')

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000
        )
        return kdf.derive(password.encode('utf-8'))

