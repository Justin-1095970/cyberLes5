import os

from flask import Flask, render_template, request, jsonify
from crypto_service import CryptoService

app = Flask(__name__)
crypto = CryptoService()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/create-key', methods=['POST'])
def create_key():
    data = request.get_json()
    key_name = data.get('key_name', '').strip()
    password = data.get('password', '').strip()
    master_password = data.get('master_password', '').strip()

    if not all([key_name, password, master_password]):
        return jsonify({'error': 'Please fill all required fields.'}), 400

    salt = os.urandom(16)
    key = crypto.generate_key(password, salt)

    key_info = crypto.save_key(key_name, key, master_password)

    return jsonify({
        'success': True,
        'key_info': {
            'key_name': key_info['key_name'],
            'created_on': key_info['created_on']
        }
    })

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    data = request.get_json()
    text = data.get('text', '').strip()
    key_name = data.get('key_name', '').strip()
    master_password = data.get('master_password', '').strip()

    if not all([text, key_name, master_password]):
        return jsonify({'error': 'fill all fields.'}), 400

    key = crypto.load_key(key_name, master_password)
    encrypted = crypto.encrypt(text, key)

    return jsonify({
        'success': True,
        'message': 'encrupted tekst'
    })

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    data = request.get_json()
    encrypted_text = data.get('encrypted_text', '').strip()
    key_name = data.get('key_name', '').strip()
    master_password = data.get('master_password', '').strip()

    if not all([encrypted_text, key_name, master_password]):
        return jsonify({'error': 'fill all fields.'}), 400

    key = crypto.load_key(key_name, master_password)
    decrypted = crypto.decrypt(encrypted_text, key)

    return jsonify({
        'success': True,
        'message': 'decrypted tekst'
    })

@app.route('/api/share-key', methods=['POST'])
def share_key():
    data = request.get_json()
    key_name = data.get('key_name', '').strip()
    master_password = data.get('master_password', '').strip()
    recipient_password = data.get('recipient_password', '').strip()

    if not all([key_name, master_password, recipient_password]):
        return jsonify({'error': 'fill fields.'}), 400

    package = crypto.share_key(key_name, master_password, recipient_password)

    return jsonify({
        'success': True,
        'package': package,
        'message': 'package made'
    })

@app.route('/api/receive-key', methods=['POST'])
def receive_key():
    data = request.get_json()
    package = data.get('package', '').strip()
    recipient_password = data.get('recipient_password', '').strip()
    new_key_name = data.get('new_key_name', '').strip()
    master_password = data.get('master_password', '').strip()

    if not all([package, recipient_password, new_key_name, master_password]):
        return jsonify({'error': 'fill fields.'}), 400

    import_info = crypto.receive_key(package, recipient_password, new_key_name, master_password)

    return jsonify({
        'success': True,
        'import_info': import_info,
        'message': 'key imported, "{new_key_name}" is now active"'
    })

if __name__ == '__main__':
    app.run(debug=True)