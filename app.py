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
    try:
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
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json()
    return jsonify({'encrypted': data['text']})

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json()
    return jsonify({'decrypted': data['text']})

if __name__ == '__main__':
    app.run(debug=True)