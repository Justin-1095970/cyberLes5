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



    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000
        )
        return kdf.derive(password.encode('utf-8'))

