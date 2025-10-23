from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json()
    return jsonify({'encrypted': data['text']})

@app.route('api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json()
    return jsonify({'decrypted': data['text']})

if __name__ == '__main__':
    app.run(debug=True)