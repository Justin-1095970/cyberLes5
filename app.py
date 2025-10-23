from flask import Flask, render_template, request, jsonify
from crypto_service import CryptoService

app = Flask(__name__)
crypto_service = CryptoService()

@app.route('/')
def index():
    return render_template('index.html')

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