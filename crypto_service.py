from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

class CryptoService:
    SALT_SIZE = 16
    KEY_SIZE = 32
    NONCE_SIZE = 12
    KDF_ITERATIONS = 100000

    @staticmethod
    def get_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=CryptoService.KEY_SIZE,
            salt=salt,
            iterations=CryptoService.KDF_ITERATIONS
        )
        return kdf.derive(password.encode('utf-8'))

    @staticmethod
    def encrypt(plaintext, password):
        if not plaintext or not password:
            raise ValueError("Invalid plaintext or password")

        salt = os.urandom(CryptoService.SALT_SIZE)
        nonce = os.urandom(CryptoService.NONCE_SIZE)

        key = CryptoService.get_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        encrypted_data = salt + nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext, password):
        if not ciphertext or not password:
            raise ValueError("Invalid ciphertext or password")